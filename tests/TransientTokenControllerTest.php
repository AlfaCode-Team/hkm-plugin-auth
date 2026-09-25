<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Infrastructure\Http\Controllers\TransientTokenController;
use Tests\Unit\Plugins\Auth\Support\FakeAuthService;

#[CoversClass(TransientTokenController::class)]
final class TransientTokenControllerTest extends TestCase
{
    private function controller(FakeAuthService $auth, Identity $identity, ?string $tenantHost = null): TransientTokenController
    {
        $request = Request::build(method: 'POST', path: '/auth/token/refresh')->withIdentity($identity);

        if ($tenantHost !== null) {
            // What Tenancy's ActiveTenantStage leaves behind on a real switch.
            $container = new \AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer(
                new \AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer(),
            );
            $container->bind('tenant.host', static fn (): string => $tenantHost);
            $request = $request->withAttribute('tenant_host', $tenantHost)->withContainer($container);
        }

        return (new TransientTokenController($auth))->setRequest($request);
    }

    public function test_session_user_gets_a_short_lived_token(): void
    {
        $response = $this->controller(new FakeAuthService(), new Identity('u1', '', ['user'], ['read'], 'session'))->refresh();

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true)['data'];
        self::assertSame('jwt', $body['access_token']);   // FakeAuthService::issueJwt
        self::assertSame('Bearer', $body['token_type']);
        self::assertSame(900, $body['expires_in']);
    }

    public function test_guest_is_rejected(): void
    {
        self::assertSame(401, $this->controller(new FakeAuthService(), Identity::guest())->refresh()->getStatusCode());
    }

    public function test_bearer_caller_cannot_mint_a_transient_token(): void
    {
        // A JWT/PAT caller (tokenType != 'session') must not refresh a transient token.
        $response = $this->controller(new FakeAuthService(), new Identity('u1', '', [], [], 'jwt'))->refresh();
        self::assertSame(401, $response->getStatusCode());
    }

    public function test_a_switched_session_cannot_mint_a_token_scoped_to_the_tenant_it_is_viewing(): void
    {
        // Tenancy's ActiveTenantStage scoped this session into `child` with a
        // per-request role; `tenant_host` is the tenant it signed in to. A JWT
        // would freeze that scope past the policy that granted it.
        $response = $this->controller(
            new FakeAuthService(),
            new Identity('u1', 'child', ['observer'], [], 'session'),
            tenantHost: 'parent',
        )->refresh();

        self::assertSame(403, $response->getStatusCode());
    }

    public function test_an_unswitched_session_on_a_tenant_host_still_gets_its_token(): void
    {
        // `tenant_host` is published on every request the stage sees, switched
        // or not — only the `tenant.host` binding marks a switch. A session
        // whose own tenant is '' must not be mistaken for a switched one.
        $request = Request::build(method: 'POST', path: '/auth/token/refresh')
            ->withIdentity(new Identity('u1', '', ['admin'], [], 'session'))
            ->withAttribute('tenant_host', 'parent');

        $response = (new TransientTokenController(new FakeAuthService()))->setRequest($request)->refresh();

        self::assertSame(200, $response->getStatusCode());
    }
}
