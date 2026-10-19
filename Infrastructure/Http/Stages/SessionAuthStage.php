<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use Plugins\Auth\API\Contracts\AuthServiceContract;
use Plugins\Auth\Application\Services\AuthService;
use Plugins\Auth\Application\Services\DeviceSessionService;
use Plugins\Auth\Domain\ValueObjects\Recaller;
use Plugins\Cookie\Infrastructure\CookieJar;
use Plugins\User\API\Contracts\UserServiceContract;
use Plugins\User\API\DTOs\UserDTO;

/**
 * SessionAuthStage — stateful authentication for browser (web + AJAX) requests.
 *
 * Why a stage and not a SecurityLayer: the session is only opened at
 * `after.load` (StartSessionStage, priority 20), which runs AFTER the
 * SecurityGateway. So token auth (JWT / PAT) attaches an Identity in the gateway,
 * and SESSION auth attaches one here — this stage is registered at `after.load`
 * with a priority just above StartSessionStage so the session is already loaded,
 * and before RouteFilterStage so the `auth` filter sees the resulting Identity.
 *
 * Precedence: a request that already carries a token-derived Identity (Bearer
 * JWT/PAT) is left untouched — the explicit credential wins. Anonymous requests
 * with a logged-in session get a `tokenType: 'session'` Identity. Everything else
 * stays guest so public routes keep working.
 */
final class SessionAuthStage implements HttpStageContract
{
    /**
     * Register right after StartSessionStage (20) so the session is loaded, and
     * before TenantContextStage (23) so a session-scoped tenant can route the DB.
     */
    public const PRIORITY = 22;

    /** Encrypted "remember me" cookie name and its lifetime (30 days). */
    public const RECALLER_COOKIE = 'remember_web';
    public const RECALLER_TTL    = 60 * 60 * 24 * 30;

    public function handle(Request $request, callable $next): Response
    {
        // A token already authenticated this request — do not override it.
        $existing = $request->identity();

        if ($existing !== null && !$existing->isGuest()) {
            return $next($request);
        }

        $container = $request->container();

        if ($container === null || !$container->has(SessionPort::class)) {
            return $next($request);
        }

        $session = $container->make(SessionPort::class);

        if (!$session instanceof SessionPort) {
            return $next($request);
        }

        $userId = (string) $session->get(AuthService::SESSION_USER, '');
        if ($userId === '') {
            // No live session — try to resurrect one from a "remember me" cookie.
            $resurrected = $this->fromRecaller($request, $container, $session);
            if ($resurrected !== null) {
                $request = $resurrected;
            }

            return $next($request);
        }


      
        // Fingerprint + device-session validation (old __DEV__ semantics): a
        // request that can't reproduce the login fingerprint, or whose server-
        // side session row was revoked/expired, loses the session outright.
        if ($container->has(DeviceSessionService::class)) {
            $devices = $container->make(DeviceSessionService::class);
            if ($devices instanceof DeviceSessionService && !$devices->verify($session, $request)) {
                // Drop the session; a remembered device keeps its row, so its
                // cookie can sign it straight back in on THIS request rather
                // than after a trip through the sign-in page.
                $devices->release($session);
                $session->invalidate();

                return $next($this->fromRecaller($request, $container, $session) ?? $request);
            }
        }

        $identity = new Identity(
            userId:      $userId,
            tenantId:    (string) $session->get(AuthService::SESSION_TENANT, ''),
            roles:       $this->stringList($session->get(AuthService::SESSION_ROLES, [])),
            permissions: $this->stringList($session->get(AuthService::SESSION_PERMISSIONS, [])),
            tokenType:   'session',
            username:    (string) $session->get(AuthService::SESSION_USERNAME, ''),
            email:       (string) $session->get(AuthService::SESSION_EMAIL, ''),
            fullName:    (string) $session->get(AuthService::SESSION_NAME, ''),
            avatarUrl:   (string) $session->get(AuthService::SESSION_AVATAR, ''),
        );

        return $next($this->attach($request, $container, $identity));
    }

    /**
     * Attach a session Identity to BOTH the request and the request-scoped
     * container.
     *
     * Why the container too: services inject Identity from the ModuleContainer,
     * which OnDemandLoader binds at LoadStage from the PRE-auth (guest) request —
     * that runs before this after.load stage. Setting it only on the request
     * would authenticate route filters (the `auth` alias) but leave the service
     * layer seeing a guest, so service-level permission checks would wrongly
     * fail. Rebinding here is safe: no service resolves Identity until
     * ExecuteStage, which runs after this stage. Token auth is unaffected — it
     * attaches its Identity in the SecurityGateway, before LoadStage, so the
     * container already holds the correct one.
     */
    private function attach(Request $request, $container, Identity $identity): Request
    {
        $container->instance(Identity::class, $identity);

        return $request->withIdentity($identity);
    }

    /**
     * Validate a "remember me" recaller cookie and, on success, re-open a full
     * session login. Returns the request carrying the rebuilt Identity, or null
     * when there is no valid recaller (request left untouched, stays guest).
     *
     * Two cookie shapes ({@see Recaller}):
     *
     *  - PER-DEVICE `d:<session id>|<token>` — resumes THAT device's
     *    `auth_sessions` row with fresh secrets (DeviceSessionService::resume).
     *    One row per browser however often it comes back, and no other
     *    device's cookie is touched.
     *  - LEGACY `<user id>|<token>` (users.remember_token, one per user) —
     *    accepted once and replaced by a per-device cookie.
     *
     * Security: tokens are matched by their stored hash and rotated on EVERY
     * use, so a stolen cookie is a single-use window. A per-device resume is a
     * compare-and-swap, so two requests racing with one cookie value cannot
     * both succeed.
     */
    private function fromRecaller(Request $request, $container, SessionPort $session): ?Request
    {
        if (!$container->has(CookieJar::class)
            || !$container->has(UserServiceContract::class)
            || !$container->has(AuthServiceContract::class)) {
            return null;
        }

        $cookies = $container->make(CookieJar::class);
        $raw     = $cookies instanceof CookieJar ? $cookies->read($request, self::RECALLER_COOKIE) : null;
        if ($raw === null || $raw === '') {
            return null;
        }

        $recaller = new Recaller($raw);
        if (!$recaller->valid()) {
            return null;
        }

        $users   = $container->make(UserServiceContract::class);
        $devices = $container->has(DeviceSessionService::class) ? $container->make(DeviceSessionService::class) : null;
        $devices = $devices instanceof DeviceSessionService ? $devices : null;
        if (!$users instanceof UserServiceContract) {
            return null;
        }

        if ($recaller->isDevice()) {
            if ($devices === null) {
                return null;
            }

            // Validate and swap the device's secrets first, so a bad cookie
            // never writes an identity. It puts the new device token and
            // fingerprint into the session; startSession() rotates the id and
            // keeps them.
            $resumed = $devices->resume($session, $request, $recaller);
            // Same gates as the legacy findByRememberToken(): canLogin()
            // (currently always true) and an active membership.
            $user = $resumed !== null ? $users->find($resumed['userId'], true, true) : null;
            if ($resumed === null || $user === null) {
                if ($resumed !== null) {
                    $devices->teardown($session); // a row for an account that may no longer sign in
                }

                return null;
            }

            $this->openSession($container, $session, $user);
            $cookies->queue(self::RECALLER_COOKIE, $resumed['recaller']->value(), maxAge: self::RECALLER_TTL);

            return $this->attach($request, $container, $this->identityFor($user));
        }

        $user = $users->findByRememberToken($recaller->token());

        // The cookie's id must match the token owner — defence against a
        // mismatched/forged pairing.
        if ($user === null || $user->id !== $recaller->id()) {
            return null;
        }

        $this->openSession($container, $session, $user);

        // Bind the resurrected session to THIS device, exactly as a password
        // login does, and give the device its own remembered row: the cookie
        // issued below is per-device from now on. Without the binding,
        // remember-me produced a session with no fingerprint and no
        // device-session row — invisible to "sign out other devices".
        //
        // The per-user token is retired first: per-device, the old cookie must
        // not be replayable; legacy (database not migrated yet, or no
        // registry), cycleRememberToken() below mints the next one anyway.
        $users->clearRememberToken($user->id);
        $fresh = $devices?->establish($session, $request, $user->id, remember: true);

        $cookies->queue(
            self::RECALLER_COOKIE,
            ($fresh ?? Recaller::make($user->id, $users->cycleRememberToken($user->id)))->value(),
            maxAge: self::RECALLER_TTL,
        );

        return $this->attach($request, $container, $this->identityFor($user));
    }

    /** Re-establish the stateful session (rotates the session id). */
    private function openSession($container, SessionPort $session, UserDTO $user): void
    {
        $auth = $container->make(AuthServiceContract::class);
        if ($auth instanceof AuthServiceContract) {
            $auth->startSession($session, $user->id, username: $user->username, email: $user->email, fullName: $user->fullName, avatarUrl: $user->avatarUrl, tenantId: $user->tenantId ?? '', roles: $user->roles, permissions: $user->permissions);

            return;
        }

        $session->put(AuthService::SESSION_USER, $user->id);
        $session->put(AuthService::SESSION_USERNAME, $user->username);
        $session->put(AuthService::SESSION_EMAIL, $user->email);
        $session->put(AuthService::SESSION_AVATAR, $user->avatarUrl);
        $session->put(AuthService::SESSION_NAME, $user->fullName);
        $session->put(AuthService::SESSION_TENANT, $user->tenantId ?? '');
        $session->put(AuthService::SESSION_ROLES, $user->roles);
        $session->put(AuthService::SESSION_PERMISSIONS, $user->permissions);
    }

    private function identityFor(UserDTO $user): Identity
    {
        return new Identity(
            userId:      $user->id,
            tenantId:    $user->tenantId ?? '',
            roles:       $user->roles,
            permissions: $user->permissions,
            tokenType:   'session',
            username:    $user->username,
            email:       $user->email,
            fullName:    $user->fullName,
            avatarUrl:   $user->avatarUrl,
        );
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }
}
