<?php

declare(strict_types=1);

namespace Plugins\Auth\Application\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use Plugins\Auth\Application\Ports\Authenticatable;
use Plugins\Auth\Application\Ports\StatefulGuard;
use Plugins\Auth\Application\Ports\SupportsBasicAuth;
use Plugins\Auth\Application\Ports\UserProvider;
use Plugins\Auth\Application\Services\AuthService;
use Plugins\Auth\Application\Services\DeviceSessionService;
use Plugins\Auth\Domain\ValueObjects\Recaller;
use Plugins\Auth\Infrastructure\Http\Stages\SessionAuthStage;
use Plugins\Cookie\Infrastructure\CookieJar;
use Plugins\User\API\Contracts\UserServiceContract;
 
/**
 * StatefulSessionGuard — the interactive login/logout guard.
 *
 * GDA-native port of the old __DEV__ SessionDriver: attempt/login/logout/once/
 * loginUsingId/validate/viaRemember/logoutOtherDevices, plus remember-me via the
 * encrypted recaller cookie. No Laravel base class — it drives the kernel
 * SessionPort, the Cookie plugin's CookieJar, and UserServiceContract.
 *
 * Read-side resolution (who is logged in on a fresh request) is also handled by
 * SessionAuthStage; this guard is what CONTROLLERS call to perform the login.
 */
final class StatefulSessionGuard implements StatefulGuard, SupportsBasicAuth
{
    use GuardBehaviour;

    private bool $viaRemember = false;
    private ?Authenticatable $lastAttempted = null;
    private ?Request $request = null;

    public function __construct(
        private readonly string $name,
        UserProvider $provider,
        private readonly SessionPort $session,
        private readonly UserServiceContract $users,
        private readonly ?CookieJar $cookies = null,
        private readonly string $recallerCookie = SessionAuthStage::RECALLER_COOKIE,
        private readonly int $rememberTtl = SessionAuthStage::RECALLER_TTL,
        private readonly ?DeviceSessionService $devices = null,
    ) {
        $this->provider = $provider;
    }

    public function setRequest(Request $request): self
    {
        $this->request     = $request;
        $this->user        = null;
        $this->viaRemember = false;

        return $this;
    }

    public function getName(): string
    {
        return $this->name;
    }

    // ── Resolution ──────────────────────────────────────────────────────────────

    /** The current user: session first, then a remember-me recaller cookie. */
    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        } 

        $userId = (string) $this->session->get(AuthService::SESSION_USER, '');
        if ($userId !== '') {
            // Fingerprint + server-side device-session validation (old __DEV__
            // semantics): a hijacked or revoked session dies here, immediately.
            // A remembered device keeps its row (DeviceSessionService::release),
            // so its own cookie can sign it back in on this same call.
            if ($this->devices !== null && $this->request !== null
                && !$this->devices->verify($this->session, $this->request)) {
                $this->devices->release($this->session);
                $this->session->invalidate();

                return $this->user = $this->userFromRecaller();
            }

            $base = $this->provider->retrieveById($userId);
            if ($base instanceof AuthUserProxy) {
                $base = $base->withSecurity(
                    $this->stringList($this->session->get(AuthService::SESSION_ROLES, [])),
                    $this->stringList($this->session->get(AuthService::SESSION_PERMISSIONS, [])),
                    (string) $this->session->get(AuthService::SESSION_TENANT, ''),
                    'session',
                );
            }

            return $this->user = $base;
        }

        return $this->user = $this->userFromRecaller();
    }

    // ── Login flows ─────────────────────────────────────────────────────────────

    public function attempt(array $credentials = [], bool $remember = false): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);
         
        $this->lastAttempted = $user;

        if ($user === null) {
            return false;
        }

        $this->login($user, $remember);

        return true;
    }

    public function validate(array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        $this->lastAttempted = $user;

        return $user !== null;
    }

    public function once(array $credentials = []): bool
    {
        if (!$this->validate($credentials) || $this->lastAttempted === null) {
            return false;
        }

        $this->setUser($this->lastAttempted);

        return true;
    }

    public function onceUsingId(string $id): Authenticatable|false
    {
        $user = $this->provider->retrieveById($id);
        if ($user === null) {
            return false;
        }

        $this->setUser($user);

        return $user;
    }

    public function loginUsingId(string $id, bool $remember = false): Authenticatable|false
    {
        $user = $this->provider->retrieveById($id);
        if ($user === null) {
            return false;
        }

        $this->login($user, $remember);

        return $user;
    }

    public function login(Authenticatable $user, bool $remember = false): void
    {
        $this->openSession($user);

        // Bind the session to this device: fingerprint + auth_sessions row. A
        // remembered sign-in gets that row's own remember-me token, so it does
        // not disturb any other device's.
        $recaller = null;
        if ($this->devices !== null && $this->request !== null) {
            $recaller = $this->devices->establish($this->session, $this->request, (string) $user->getAuthIdentifier(), $remember);
        }

        if ($remember) {
            $recaller !== null
                ? $this->queueCookie($recaller)
                // No device registry, or its database is not migrated yet.
                : $this->queueRecaller((string) $user->getAuthIdentifier());
        }

        $this->setUser($user);
    }

    /** Write the signed-in identity into a freshly rotated session. */
    private function openSession(Authenticatable $user): void
    {
        $identity = $user->identity();

        // Session-fixation defence: rotate on privilege change.
        $this->session->regenerate();
        $this->session->put(AuthService::SESSION_USER, $identity->userId);
        $this->session->put(AuthService::SESSION_ROLES, $identity->roles);
        $this->session->put(AuthService::SESSION_PERMISSIONS, $identity->permissions);
        $this->session->put(AuthService::SESSION_TENANT, $identity->tenantId);
        $this->session->put(AuthService::SESSION_USERNAME, $identity->username);
        $this->session->put(AuthService::SESSION_EMAIL, $identity->email);
        $this->session->put(AuthService::SESSION_NAME, $identity->fullName);
        $this->session->put(AuthService::SESSION_AVATAR, $identity->avatarUrl);
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    public function logout(): void
    {
        $userId = $this->id();

        if ($userId !== null && $userId !== '') {
            $this->users->clearRememberToken($userId);
        }
        $this->cookies?->forget($this->recallerCookie);
        $this->devices?->teardown($this->session);
        $this->session->invalidate();
        $this->forgetUser();
        $this->viaRemember = false;
    }

    /**
     * Invalidate every OTHER session/remember-me for this user by cycling the
     * remember token, after re-verifying the password. Returns the current user.
     */
    public function logoutOtherDevices(string $password): ?Authenticatable
    {
        $user = $this->user();
        if ($user === null) {
            return null;
        }

        // Re-verify the password before rotating (defence against a hijacked session).
        if ($this->users->verifyCredentials($user->getEmail(), $password) === null
            && $this->users->verifyCredentials($user->getUsername(), $password) === null) {
            return null;
        }

        // Kill every OTHER device's server-side session (old semantics). Their
        // per-device remember-me lives on those rows, so it dies with them.
        if ($this->devices !== null && $this->request !== null) {
            $this->devices->revokeOthers($this->session, $this->request, $user->getAuthIdentifier());

            // Legacy per-user cookies elsewhere die too.
            $this->users->clearRememberToken($user->getAuthIdentifier());

            // A copy of THIS device's cookie taken earlier stops working as
            // well, if this device is remembered. One that is not remembered
            // does not become remembered by asking.
            $recaller = $this->devices->rotateRemember($this->session);
            if ($recaller !== null) {
                $this->queueCookie($recaller);
            }

            return $user;
        }

        $this->queueRecaller($user->getAuthIdentifier()); // no registry: legacy rotate + reissue

        return $user;
    }

    public function viaRemember(): bool
    {
        return $this->viaRemember;
    }

    // ── HTTP Basic auth ─────────────────────────────────────────────────────────

    public function basic(string $field = 'email', array $extraConditions = []): ?Response
    {
        if ($this->check()) {
            return null;
        }

        $creds = $this->basicCredentials($field, $extraConditions);
        if ($creds !== null && $this->attempt($creds)) {
            return null;
        }

        return $this->basicChallenge();
    }

    public function onceBasic(string $field = 'email', array $extraConditions = []): ?Response
    {
        $creds = $this->basicCredentials($field, $extraConditions);
        if ($creds !== null && $this->once($creds)) {
            return null;
        }

        return $this->basicChallenge();
    }

    /** @return array<string,string>|null decoded Basic credentials */
    private function basicCredentials(string $field, array $extraConditions): ?array
    {
        $header = $this->request?->header('Authorization') ?? '';
        if (!str_starts_with($header, 'Basic ')) {
            return null;
        }

        $decoded = base64_decode(substr($header, 6), true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            return null;
        }

        [$user, $password] = explode(':', $decoded, 2);

        return [$field => $user, 'password' => $password] + $extraConditions;
    }

    private function basicChallenge(): Response
    {
        return Response::unauthorized('Invalid credentials.')
            ->withHeader('WWW-Authenticate', 'Basic realm="' . $this->name . '"');
    }

    public function getLastAttempted(): ?Authenticatable
    {
        return $this->lastAttempted;
    }

    // ── Remember-me internals ────────────────────────────────────────────────────

    private function userFromRecaller(): ?Authenticatable
    {
        if ($this->cookies === null || $this->request === null) {
            return null;
        }

        $raw = $this->cookies->read($this->request, $this->recallerCookie);
        if ($raw === null || $raw === '') {
            return null;
        }

        $recaller = new Recaller($raw);
        if (!$recaller->valid()) {
            return null;
        }

        // Per-device cookie: resume THAT device's row with fresh secrets. The
        // user is looked up with the same gates as the legacy token lookup
        // (findByRememberToken: canLogin() — currently always true — and an
        // active membership), which retrieveById() applies via find(id, true, true).
        if ($recaller->isDevice()) {
            if ($this->devices === null) {
                return null;
            }

            $resumed = $this->devices->resume($this->session, $this->request, $recaller);
            $user    = $resumed !== null ? $this->provider->retrieveById($resumed['userId']) : null;
            if ($resumed === null || $user === null) {
                return null;
            }

            // resume() already wrote this device's new token and fingerprint
            // into the session; openSession() rotates the id and KEEPS them
            // (Store::regenerate() keeps attributes). Validating before opening
            // is the point: a bad cookie never writes an identity.
            $this->openSession($user);
            $this->queueCookie($resumed['recaller']);
            $this->viaRemember = true;
            $this->setUser($user);

            return $user;
        }

        // Legacy per-user cookie: accepted once, then replaced by a per-device
        // one (login(remember: true) opens this device's own remembered row).
        $user = $this->provider->retrieveByToken($recaller->token());
        if ($user === null || $user->getAuthIdentifier() !== $recaller->id()) {
            return null;
        }

        // Retire the per-user token first, so the old cookie cannot be replayed.
        // If this database cannot store a per-device token yet, login() falls
        // back to minting a fresh legacy one, which this must not then clear.
        $this->users->clearRememberToken((string) $user->getAuthIdentifier());
        $this->viaRemember = true;
        $this->login($user, true);

        return $user;
    }

    private function queueCookie(Recaller $recaller): void
    {
        $this->cookies?->queue($this->recallerCookie, $recaller->value(), maxAge: $this->rememberTtl);
    }

    private function queueRecaller(string $userId): void
    {
        if ($this->cookies === null) {
            return;
        }

        $token = $this->users->cycleRememberToken($userId);
        $this->cookies->queue(
            $this->recallerCookie,
            Recaller::make($userId, $token)->value(),
            maxAge: $this->rememberTtl,
        );
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        return \is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
    }
}
