<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Container\CoreContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Container\ModuleContainer;
use AlfacodeTeam\PhpServicePlatform\Kernel\Database\TransactionManager;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Provider;

/**
 * Auth state belongs to the tenant the person SIGNED IN to.
 *
 * Tenancy's ActiveTenantStage lets a signed-in user switch the tenant whose
 * data they are working in. It re-points `DatabasePort` at the selection and
 * publishes the sign-in connection as `tenant.host.db`. Auth's credential
 * tables exist in every tenant database (they come from the tenant template),
 * so a store that followed the switch would not fail — it would find an empty
 * table, and a logout would revoke nothing.
 *
 * The transaction manager is the binding asserted here because it is the one
 * that must move WITH the repositories: if they stayed on the sign-in tenant
 * and it followed the switch, every auth write would be bracketed on the wrong
 * database. It is resolved through the same `signInDb()` helper as
 * `auth_sessions`, `refresh_tokens` and `personal_access_tokens`.
 */
final class SignInConnectionTest extends TestCase
{
    private function container(): ModuleContainer
    {
        $container = new ModuleContainer(new CoreContainer());
        $container->setScope('auth.identity');
        (new Provider())->register($container);

        return $container;
    }

    /** The DatabasePort a TransactionManager was built around. */
    private function connectionOf(TransactionManager $tx): DatabasePort
    {
        return (new \ReflectionProperty($tx, 'db'))->getValue($tx);
    }

    public function test_without_a_switch_auth_uses_the_request_connection(): void
    {
        $container = $this->container();
        $request   = $this->createStub(DatabasePort::class);
        $container->instance(DatabasePort::class, $request);

        self::assertSame($request, $this->connectionOf($container->make('auth.transaction')));
    }

    public function test_after_a_switch_auth_stays_on_the_sign_in_connection(): void
    {
        $container = $this->container();
        $signIn    = $this->createStub(DatabasePort::class);
        $selected  = $this->createStub(DatabasePort::class);

        // What ActiveTenantStage leaves behind after a switch.
        $container->instance('tenant.host.db', $signIn);
        $container->instance(DatabasePort::class, $selected);

        $used = $this->connectionOf($container->make('auth.transaction'));

        self::assertSame($signIn, $used, 'auth must not follow the switch');
        self::assertNotSame($selected, $used);
    }
}
