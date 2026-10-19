<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Database\TransactionManager;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\DomainEventCollector;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Audit\Application\Services\AuditService;
use Plugins\Auth\API\Contracts\AuthServiceContract;
use Plugins\Auth\Application\Services\AuthService;
use Plugins\Auth\Application\Services\DeviceSessionService;
use Plugins\Auth\Domain\ValueObjects\Recaller;
use Plugins\Auth\Infrastructure\Http\Stages\SessionAuthStage;
use Plugins\Auth\Infrastructure\Persistence\DeviceSessionRepository;
use Plugins\Auth\Infrastructure\Persistence\PersonalAccessTokenRepository;
use Plugins\Cookie\Infrastructure\CookieJar;
use Plugins\Database\Infrastructure\Drivers\SQLiteConfiguration;
use Plugins\Database\Infrastructure\Persistence\MultiDriverDatabaseAdapter;
use Plugins\User\API\Contracts\UserServiceContract;
use Plugins\User\Application\Services\UserService;
use Plugins\User\Domain\Entities\User;
use Tests\Unit\Plugins\Auth\Support\FakeSession;
use Tests\Unit\Plugins\Auth\Support\RecordingDatabasePort;
use Tests\Unit\Plugins\User\Support\FakeCache;
use Tests\Unit\Plugins\User\Support\FakeDatabasePort;
use Tests\Unit\Plugins\User\Support\FakeHasher;
use Tests\Unit\Plugins\User\Support\FakeOutbox;
use Tests\Unit\Plugins\User\Support\FakeUserStore;

/**
 * The request path of per-device remember-me: SessionAuthStage with the device
 * registry wired, its rows in a real (SQLite) `auth_sessions`, the real
 * UserService over an in-memory store.
 *
 * The legacy-only path (no registry) stays covered by SessionAuthStageRememberTest.
 */
#[CoversClass(SessionAuthStage::class)]
final class SessionAuthStageDeviceRememberTest extends TestCase
{
    private const string USER_ID = 'user-device-1';
    private const string LEGACY_TOKEN = 'plaintext-legacy-token';

    private FakeUserStore $store;
    private FakeSession $session;
    private MultiDriverDatabaseAdapter $db;
    private DeviceSessionService $devices;

    protected function setUp(): void
    {
        $this->db = new MultiDriverDatabaseAdapter(new SQLiteConfiguration(':memory:'));
        $this->db->execute('CREATE TABLE auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id CHAR(32) NOT NULL UNIQUE, user_id CHAR(31) NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE, remember_hash CHAR(64) NULL, fingerprint CHAR(64) NULL,
            ip VARCHAR(45) NULL, user_agent VARCHAR(191) NULL, last_seen_at TIMESTAMP NULL,
            expires_at TIMESTAMP NOT NULL, revoked_at TIMESTAMP NULL, created_at TIMESTAMP NULL)');
        $this->devices = new DeviceSessionService(new DeviceSessionRepository($this->db));
    }

    /** A fresh request container and session over the SAME user store and device table. */
    private function container(): ModuleContainer
    {
        $this->session = new FakeSession();
        if (isset($this->store)) {
            return $this->wire();
        }

        $this->store = new FakeUserStore();
        $user = User::reconstitute([
            'user_id'           => self::USER_ID,
            'username'          => 'remembered',
            'email'             => 'remembered@example.com',
            'password_hash'     => str_repeat('a', 60),
            'email_verified_at' => '2026-01-01 00:00:00',
            'created_at'        => '2026-01-01 00:00:00',
        ]);
        $this->store->insert($user); // by reference
        $this->store->rememberTokens[self::USER_ID] = hash('sha256', self::LEGACY_TOKEN);

        return $this->wire();
    }

    private function wire(): ModuleContainer
    {
        $users = new UserService(
            repository:  $this->store,
            transaction: new TransactionManager(new FakeDatabasePort()),
            collector:   new DomainEventCollector(),
            outbox:      new FakeOutbox(),
            eventBus:    new EventBus(new CoreContainer()),
            hasher:      new FakeHasher(),
            identity:    Identity::guest(),
            cache:       new FakeCache(),
            audit:       new AuditService(writer: null, sink: static fn(string $l) => null, actorId: 'actor'),
        );

        $container = new ModuleContainer(new CoreContainer());
        $container->setScope('auth.identity');
        $container->instance(CookieJar::class, new CookieJar()); // no encrypter: raw values
        $container->instance(UserServiceContract::class, $users);
        $container->instance(AuthServiceContract::class, new AuthService(
            tokens:    new PersonalAccessTokenRepository(new RecordingDatabasePort()),
            hasher:    new FakeHasher(),
            jwtSecret: 'a-test-secret-at-least-32-chars-long!!',
        ));
        $container->instance(SessionPort::class, $this->session);
        $container->instance(DeviceSessionService::class, $this->devices);

        return $container;
    }

    /** @return array{0: ?Identity, 1: ?string} the identity the next stage saw, and the remember cookie queued */
    private function serve(ModuleContainer $container, array $cookies, string $ip = '10.0.0.1'): array
    {
        $request = Request::build('GET', '/dashboard', headers: ['User-Agent' => 'Phone'], cookies: $cookies, server: ['REMOTE_ADDR' => $ip])
            ->withContainer($container);

        $seen = null;
        (new SessionAuthStage())->handle($request, static function (Request $req) use (&$seen): Response {
            $seen = $req->identity();

            return Response::noContent();
        });

        $queued = null;
        foreach ($container->make(CookieJar::class)->applyTo(Response::noContent())->headers->getCookies() as $cookie) {
            if ($cookie->getName() === SessionAuthStage::RECALLER_COOKIE) {
                $queued = $cookie->getValue();
            }
        }

        return [$seen, $queued];
    }

    public function test_a_per_device_cookie_signs_the_device_back_in_and_rotates_only_its_own_cookie(): void
    {
        $container = $this->container();
        $cookie = $this->devices->establish(new FakeSession(), Request::build('GET', '/', server: ['REMOTE_ADDR' => '10.0.0.1']), self::USER_ID, remember: true);

        [$identity, $queued] = $this->serve($container, [SessionAuthStage::RECALLER_COOKIE => $cookie->value()]);

        self::assertSame(self::USER_ID, $identity?->userId);
        self::assertSame('session', $identity?->tokenType);
        self::assertNotNull($queued);
        self::assertTrue((new Recaller($queued))->isDevice());
        self::assertNotSame($cookie->value(), $queued, 'rotated on use');
        self::assertCount(1, $this->db->query('SELECT * FROM auth_sessions'), 'the same row, not a new one');
        self::assertSame(hash('sha256', self::LEGACY_TOKEN), $this->store->rememberTokens[self::USER_ID], "the per-user token is not this device's business");
    }

    public function test_a_legacy_cookie_is_accepted_once_and_upgraded_to_a_per_device_one(): void
    {
        $container = $this->container();

        [$identity, $queued] = $this->serve($container, [SessionAuthStage::RECALLER_COOKIE => self::USER_ID . '|' . self::LEGACY_TOKEN]);

        self::assertSame(self::USER_ID, $identity?->userId);
        self::assertTrue((new Recaller((string) $queued))->isDevice(), 'the replacement cookie is per-device');
        self::assertArrayNotHasKey(self::USER_ID, $this->store->rememberTokens, 'the legacy token is retired');

        // The old legacy cookie no longer works.
        [$again] = $this->serve($this->container(), [SessionAuthStage::RECALLER_COOKIE => self::USER_ID . '|' . self::LEGACY_TOKEN]);
        self::assertNull($again);
    }

    public function test_a_remembered_session_that_fails_its_check_is_signed_back_in_on_the_same_request(): void
    {
        $container = $this->container();
        // Signed in and remembered from 10.0.0.1 …
        $cookie = $this->devices->establish($this->session, Request::build('GET', '/', headers: ['User-Agent' => 'Phone'], server: ['REMOTE_ADDR' => '10.0.0.1']), self::USER_ID, remember: true);
        $this->session->put(AuthService::SESSION_USER, self::USER_ID);

        // … and the next request comes from another network.
        [$identity, $queued] = $this->serve($container, [SessionAuthStage::RECALLER_COOKIE => $cookie->value()], ip: '172.16.0.9');

        self::assertSame(self::USER_ID, $identity?->userId, 'not bounced to the sign-in page');
        self::assertNotNull($queued);
        self::assertCount(1, $this->db->query('SELECT * FROM auth_sessions WHERE revoked_at IS NULL'));
    }

    public function test_a_per_device_cookie_for_a_revoked_device_stays_guest(): void
    {
        $container = $this->container();
        $here = new FakeSession();
        $cookie = $this->devices->establish($here, Request::build('GET', '/', server: ['REMOTE_ADDR' => '10.0.0.1']), self::USER_ID, remember: true);
        $this->devices->teardown($here); // signed out on that device

        [$identity, $queued] = $this->serve($container, [SessionAuthStage::RECALLER_COOKIE => $cookie->value()]);

        self::assertNull($identity);
        self::assertNull($queued);
    }
}
