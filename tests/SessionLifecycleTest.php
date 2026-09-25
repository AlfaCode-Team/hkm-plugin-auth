<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\EventListenerContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\IntegrationEventContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Infrastructure\Http\Controllers\SessionAuthController;
use Plugins\Auth\Infrastructure\Http\Controllers\SessionStartController;
use Plugins\Auth\Infrastructure\Http\Stages\FreshSessionStage;
use Plugins\Session\Infrastructure\Handlers\ArraySessionHandler;
use Plugins\Session\Infrastructure\Http\StartSessionStage;
use Plugins\Session\Infrastructure\Store;

/** Records every event it is handed. Static because the bus builds it by class name. */
final class RecordingListener implements EventListenerContract
{
    /** @var list<array{string, array<string, mixed>}> */
    public static array $seen = [];

    public function handle(IntegrationEventContract $event): void
    {
        self::$seen[] = [$event->name(), $event->payload()];
    }
}

/**
 * A sign-in page starts from a clean session, and a completed sign-in passes
 * through /auth/session/start exactly once so other plugins can set up the new
 * session — see FreshSessionStage and SessionStartController.
 */
final class SessionLifecycleTest extends TestCase
{
    protected function setUp(): void
    {
        RecordingListener::$seen = [];
    }

    // ── fresh-session ────────────────────────────────────────────────────────

    public function test_a_signed_out_visitor_gets_a_new_session_that_keeps_only_what_the_page_needs(): void
    {
        $session = $this->session([
            'tenancy.active_tenant.host' => 'stale choice',
            'half.finished.flow'         => 'stale',
            StartSessionStage::PREVIOUS_URL => '/billing',
        ]);
        $session->flash('status', 'Your password was reset.');
        $before = $session->id();

        $this->fresh(Request::build('GET', '/login'), $session);

        self::assertNotSame($before, $session->id(), 'a new session id');
        self::assertNull($session->get('tenancy.active_tenant.host'));
        self::assertNull($session->get('half.finished.flow'));
        self::assertSame('/billing', $session->get(StartSessionStage::PREVIOUS_URL), 'the login redirect still knows where to return');
        self::assertSame('Your password was reset.', $session->get('status'), 'flash messages survive');
        self::assertSame([['auth.session.reset', []]], RecordingListener::$seen);
    }

    public function test_a_signed_in_visitor_is_left_alone(): void
    {
        $session = $this->session(['auth.user' => 'user-1']);
        $before  = $session->id();

        $this->fresh(Request::build('GET', '/login')->withIdentity(Identity::asUser('user-1', '')), $session);

        self::assertSame($before, $session->id());
        self::assertSame('user-1', $session->get('auth.user'));
        self::assertSame([], RecordingListener::$seen);
    }

    public function test_a_post_is_never_touched(): void
    {
        $session = $this->session(['half.finished.flow' => 'kept']);

        $this->fresh(Request::build('POST', '/login'), $session);

        self::assertSame('kept', $session->get('half.finished.flow'));
        self::assertSame([], RecordingListener::$seen);
    }

    public function test_an_empty_session_is_not_replaced(): void
    {
        $session = $this->session();

        $this->fresh(Request::build('GET', '/login'), $session);

        self::assertFalse($session->shouldPersist(), 'a bot fetching /login must not be handed a session cookie');
    }

    // ── /auth/session/start ──────────────────────────────────────────────────

    public function test_session_start_announces_the_sign_in_once_then_redirects(): void
    {
        $session = $this->session([SessionStartController::PENDING => true]);

        $first = $this->start('/dashboard?tab=2', $session, Identity::asUser('user-1', 'tenant-a'));

        self::assertSame(302, $first->getStatusCode());
        self::assertSame('/dashboard?tab=2', $first->headers->get('Location'));
        self::assertSame([['auth.session.started', ['userId' => 'user-1', 'tenantId' => 'tenant-a']]], RecordingListener::$seen);

        $this->start('/dashboard', $session, Identity::asUser('user-1', 'tenant-a'));
        self::assertCount(1, RecordingListener::$seen, 'a second visit — or a link on another site — must not reset state again');
    }

    public function test_session_start_without_a_pending_sign_in_only_redirects(): void
    {
        $this->start('/', $this->session(), Identity::asUser('user-1', ''));

        self::assertSame([], RecordingListener::$seen);
    }

    public function test_session_start_refuses_to_redirect_off_site(): void
    {
        foreach (['https://evil.test/', '//evil.test/', '/\\evil.test', 'relative'] as $next) {
            self::assertSame('/', $this->start($next, $this->session(), Identity::asUser('user-1', ''))->headers->get('Location'), $next);
        }
    }

    public function test_login_is_routed_through_session_start(): void
    {
        self::assertSame('/auth/session/start?next=%2Fbilling%3Fa%3D1', SessionStartController::through('/billing?a=1'));
    }

    // ── /auth/logout answers ─────────────────────────────────────────────────

    private function logoutFrom(array $headers, array $body = []): Response
    {
        return SessionAuthController::afterLogout(Request::build('POST', '/auth/logout', headers: $headers, body: $body));
    }

    public function test_a_form_logout_returns_to_the_page_it_came_from(): void
    {
        $response = $this->logoutFrom(['Accept' => 'text/html'], ['redirectTo' => '/editions/42?tab=votes']);

        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/editions/42?tab=votes', $response->headers->get('Location'));
    }

    public function test_a_form_logout_without_redirect_to_falls_back_to_the_referer_path(): void
    {
        $response = $this->logoutFrom(['Accept' => 'text/html', 'Referer' => 'https://app.test/settings?x=1']);

        self::assertSame('/settings?x=1', $response->headers->get('Location'));
    }

    public function test_a_logout_target_can_never_leave_the_site(): void
    {
        foreach (['https://evil.test/phish', '//evil.test/phish', '/\\evil.test/phish'] as $target) {
            $location = (string) $this->logoutFrom(['Accept' => 'text/html'], ['redirectTo' => $target])->headers->get('Location');

            // A path on THIS site: no host, and no '//' or backslash a browser
            // would read as one.
            self::assertStringStartsWith('/', $location, $target);
            self::assertStringStartsNotWith('//', $location, $target);
            self::assertStringNotContainsString('\\', $location, $target);
            self::assertNull(parse_url($location, PHP_URL_HOST), $target);
        }
    }

    public function test_a_pageflow_logout_becomes_a_full_page_load(): void
    {
        $response = $this->logoutFrom(['X-Pageflow' => 'true', 'X-Requested-With' => 'XMLHttpRequest', 'Referer' => 'https://app.test/editions']);

        self::assertSame(409, $response->getStatusCode());
        self::assertSame('/editions', $response->headers->get('X-Pageflow-Location'));
    }

    public function test_a_json_logout_is_still_a_204(): void
    {
        self::assertSame(204, $this->logoutFrom(['Accept' => 'application/json', 'X-Requested-With' => 'XMLHttpRequest'])->getStatusCode());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private function fresh(Request $request, SessionPort $session): void
    {
        (new FreshSessionStage())->handle($request->withContainer($this->container($session)), static fn (): Response => Response::empty());
    }

    private function start(string $next, SessionPort $session, Identity $identity): Response
    {
        $request = Request::build('GET', '/auth/session/start', query: ['next' => $next])
            ->withIdentity($identity)
            ->withContainer($this->container($session));

        return (new SessionStartController())->setRequest($request)->start();
    }

    private function container(SessionPort $session): ModuleContainer
    {
        $container = new ModuleContainer(new CoreContainer());
        $container->instance(SessionPort::class, $session);

        $bus = (new EventBus(new CoreContainer()))->forContainer($container);
        $bus->subscribe('auth.session.reset', RecordingListener::class);
        $bus->subscribe('auth.session.started', RecordingListener::class);
        $container->instance(EventBus::class, $bus);

        return $container;
    }

    /** A started session, as StartSessionStage leaves it, holding $data. */
    private function session(array $data = []): Store
    {
        $handler = new ArraySessionHandler();
        $store   = new Store('test', $handler);

        if ($data !== []) {
            $seed = new Store('test', $handler);
            $seed->start();
            foreach ($data as $key => $value) {
                $seed->put($key, $value);
            }
            $seed->save();
            $store->start($seed->id());

            return $store;
        }

        $store->start();

        return $store;
    }
}
