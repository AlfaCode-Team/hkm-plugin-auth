<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Controllers;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use Plugins\Auth\API\IntegrationEvents\AuthSessionIntegrationEvent;
use Plugins\Auth\Application\Ports\Authenticatable;
use Plugins\Auth\Application\Ports\StatefulGuard;
use Plugins\Auth\Application\Services\DeviceSessionService;
use Plugins\Session\Infrastructure\Http\StartSessionStage;
use Plugins\User\API\Contracts\UserServiceContract;
use Plugins\User\API\Support\VerificationBinding;
use Project\Http\Controllers\ApiController;
use Project\Http\Controllers\Concerns\InteractsWithAuthManager;

/**
 * Stateful (session) login/logout for browser + AJAX clients.
 *
 * Everything runs through the AuthManager guard — `$this->auth('web')` — exactly
 * the old `$auth->guard('web')->attempt()/logout()` ergonomic. The 'web' guard's
 * driver owns credential verification, the session write, remember-me, and the
 * device-session registry; this controller only translates request → guard call
 * → Response. Incoming-token verification (for token/JWT callers) still happens
 * in the SecurityGateway before modules load — that is the one thing the guard
 * cannot own under GDA.
 *
 *   POST   /auth/login                { identifier|email, password, remember? }
 *   POST   /auth/logout               → 204
 *   GET    /auth/me                   → current identity
 *   GET    /auth/sessions             → active device sessions
 *   DELETE /auth/sessions/{id}        → revoke one device
 *   POST   /auth/logout-other-devices { password } → revoke all OTHER devices
 *
 * CSRF: session/cookie endpoints (NOT under /api) are guarded by the kernel's
 * CsrfTokenLayer — send the token via `X-CSRF-Token` (AJAX) or `_csrf_token`.
 */
final class SessionAuthController extends ApiController
{
    use InteractsWithAuthManager;

    public function __construct(
        // Only the device-management endpoints (list / revoke-by-id) touch the
        // registry directly; the login/logout flow goes through the guard.
        private readonly ?DeviceSessionService $devices = null,
        /**
         * Optional. Used for exactly one thing: after the guard has already
         * refused, asking whether the credentials were in fact CORRECT and the
         * account is merely unverified — the single failure the person can act
         * on. Unbound, login falls back to the generic 401.
         */
        private readonly ?UserServiceContract $users = null,
    ) {
    }

    public function login(): Response
    {
        $request    = $this->resolveRequest();
        $identifier = trim((string) ($request->input('identifier') ?? $request->input('email')));
        $password   = (string) $request->input('password');

        if ($identifier === '' || $password === '') {
            return $this->unprocessable([
                'identifier' => $identifier === '' ? 'An email or username is required.' : '',
                'password'   => $password === '' ? 'A password is required.' : '',
            ]);
        }

        $guard       = $this->auth('web');
        $credentials = $this->credentials($identifier, $password);

        $previous    = null;

        // ALREADY SIGNED IN — a sign-in form left open in another tab, or one
        // shown before the `guest` filter was on its page. Running attempt() on
        // top of the session is wrong both ways: for the same account it rotates
        // the session of someone who was signed in all along; for ANOTHER
        // account, login() rotates the id but keeps the attributes, so the new
        // person inherits what the old one's session held (a chosen
        // organisation, a half-finished flow).
        $current  = $guard->user();
        $stateful = $guard->stateful();
        $fresh    = true;
        $outcome  = null;
        if ($current !== null && $stateful !== null) {
            $outcome = self::whenSignedIn($stateful, $current, $credentials);
            if ($outcome === self::SAME_ACCOUNT) {
                // Nothing to do: send them on, without a new session.
                $fresh = false;
            } elseif ($outcome === self::OTHER_ACCOUNT) {
                // The password is right, so switching is what was asked for.
                // Only NOW is the current person signed out — a wrong password
                // never costs them their session — completely, and other plugins
                // told so, so the next person starts clean. The page to return
                // to lives in the session being discarded: read it first.
                $previous = $this->sessionPull(StartSessionStage::PREVIOUS_URL);
                $guard->logout();
                $this->announceSessionReset();
            }
            // REFUSED answers exactly as for a signed-out visitor, without a
            // second attempt(): that would count the one wrong password twice
            // towards the lockout.
        }

        // The 'web' guard's driver verifies credentials, opens the session,
        // binds the device fingerprint + auth_sessions row, and (when asked)
        // queues the remember-me recaller — all internally.
        if ($outcome === self::REFUSED
            || ($fresh && !$guard->attempt($credentials, $request->boolean('remember')))) {
            // COMPATIBILITY PATH — normally unreachable now.
            //
            // Under soft verification (User::canLogin() since user v2.2.0) an
            // unconfirmed address no longer refuses sign-in: the attempt above
            // SUCCEEDS and the banner, not a 401, is what asks the person to
            // verify. This branch survives for a deployment still running an
            // older User plugin, where the hard gate is intact and a correct
            // password on an unverified account lands here — reported as
            // "Invalid credentials." it would send everyone who just signed up
            // back to retype a password that was right, with no hint of what to
            // do, so it is named and pointed at the page that fixes it.
            //
            // Disclosure is safe because the User service only answers once the
            // password matches: someone without the credentials still sees the
            // uniform 401 below, and account existence stays unrevealed.
            $pending = $this->users?->credentialsAwaitingVerification($identifier, $password);
            if ($pending !== null) {
                return $this->emailUnverified($pending);
            }

            // Uniform message — never reveals whether the account exists or is locked.
            return Response::unauthorized('Invalid credentials.');
        }

        // Where to send the user after sign-in, first match wins:
        //   1. an explicit `redirectTo` on the login request itself (query or
        //      body — e.g. /auth/login?redirectTo=/billing),
        //   2. the previous page recorded by the Session plugin's
        //      StartSessionStage — PULLED (one-time) either way, so the
        //      fulfilled intent never goes stale,
        //   3. '/'.
        // Both candidates pass the same open-redirect guard.
        $previous ??= $this->sessionPull(StartSessionStage::PREVIOUS_URL);
        $redirect = $this->safeRedirect($request->input('redirectTo'))
            ?? $this->safeRedirect($previous)
            ?? '/';

        // …via /auth/session/start, so the first page view of the new session
        // is where other plugins set up their per-user state (see
        // SessionStartController). AUTH_SESSION_START=false restores the direct
        // redirect for a deployment that disables that route.
        // Not for the same account signing in again: no new session started.
        if ($fresh && self::sessionStartEnabled()) {
            $this->sessionPut(SessionStartController::PENDING, true);
            $redirect = SessionStartController::through($redirect);
        }

        // Browser form POST → real redirect; AJAX/SPA callers get the target in
        // the payload and navigate client-side.
        if (!$request->expectsJson()) {
            return Response::redirect($redirect);
        }

        return $this->ok(['user' => $this->shape($guard->user()), 'redirectTo' => $redirect]);
    }

    public const string SAME_ACCOUNT  = 'same';
    public const string OTHER_ACCOUNT = 'other';
    public const string REFUSED       = 'refused';

    /**
     * Someone already signed in submitted the sign-in form: whose credentials
     * are these?
     *
     *   SAME_ACCOUNT   the current person, password right — nothing to do;
     *   OTHER_ACCOUNT  someone else, password right — switch accounts;
     *   REFUSED        the credentials are wrong — the current person stays.
     *
     * validate() checks the password without signing anyone in. Which account
     * it matched is read from the guard when it can say (StatefulSessionGuard's
     * getLastAttempted()); a guard that cannot is treated as OTHER_ACCOUNT,
     * which costs a needless sign-out and sign-in and never leaves the wrong
     * person signed in.
     *
     * @param array<string,string> $credentials
     * @return self::SAME_ACCOUNT|self::OTHER_ACCOUNT|self::REFUSED
     */
    public static function whenSignedIn(StatefulGuard $guard, Authenticatable $current, array $credentials): string
    {
        if (!$guard->validate($credentials)) {
            return self::REFUSED;
        }

        $matched = method_exists($guard, 'getLastAttempted') ? $guard->getLastAttempted() : null;

        return $matched instanceof Authenticatable
            && (string) $matched->getAuthIdentifier() === (string) $current->getAuthIdentifier()
            ? self::SAME_ACCOUNT
            : self::OTHER_ACCOUNT;
    }

    /** Tell other plugins the session changed hands (Tenancy forgets the chosen organisation). */
    private function announceSessionReset(): void
    {
        $container = $this->resolveRequest()->container();
        if ($container !== null && $container->has(EventBus::class)) {
            $container->make(EventBus::class)->dispatch(
                new AuthSessionIntegrationEvent(AuthSessionIntegrationEvent::RESET),
            );
        }
    }

    /**
     * 403 for "the password was right, the address was never confirmed".
     *
     * Distinct from the 401 so the client can route to the verification page
     * rather than re-prompting for a password that is already correct. The
     * address itself is NOT echoed back — the caller typed it, and the account
     * it belongs to is named only by the binding, which is an opaque keyed hash.
     *
     * That binding is what makes the next screen work: it admits this browser
     * to /verify-email and pins any resend there to THIS address, so the person
     * refused here can get a fresh link without a second sign-in attempt.
     */
    private function emailUnverified(string $email): Response
    {
        $this->queueCookie(
            VerificationBinding::COOKIE,
            VerificationBinding::hash($email),
            VerificationBinding::MINUTES,
        );

        return Response::json([
            'error' => [
                'code'    => 'auth.email_unverified',
                'message' => 'Your email address has not been verified yet. '
                    . 'Open the link we emailed you, or request a new one, then sign in.',
                'verifyUrl' => '/verify-email',
            ],
        ], 403);
    }

    /**
     * Validate a redirect candidate into a safe INTERNAL target, or null when
     * it is unusable. Accepts only a relative path ('/…'); rejects
     * protocol-relative ('//…'), backslash tricks and absolute URLs — the
     * open-redirect guard for both the request param and the session value.
     */
    private function safeRedirect(mixed $candidate): ?string
    {
        return SessionStartController::safeTarget($candidate);
    }

    private static function sessionStartEnabled(): bool
    {
        return !\in_array(strtolower(trim((string) (env('AUTH_SESSION_START') ?? '1'))), ['0', 'false', 'off', 'no'], true);
    }

    public function logout(): Response
    {
        // Guard tears down the session, revokes this device's registry row, and
        // clears the remember-me token + cookie.
        $this->auth('web')->logout();

        return self::afterLogout($this->resolveRequest());
    }

    /**
     * What a sign-out answers, by who asked:
     *
     *   - a browser FORM (a hard POST — Pageflow's router.logout(), or a plain
     *     <form method="post">) → 303 to `redirectTo`, else the page it was
     *     submitted from, else '/'. The browser reloads that page as a
     *     signed-out visitor; a page that needs sign-in sends them on to it.
     *   - a Pageflow XHR (router.post) → 409 + X-Pageflow-Location to the same
     *     target, which the client turns into a full page load. A 204 there was
     *     not a Pageflow response, so the client reported it as an error and left
     *     the signed-in page on screen.
     *   - any other JSON caller → 204, unchanged.
     *
     * Every target is reduced to a same-origin path, so neither `redirectTo`
     * nor the Referer can send the browser off-site.
     */
    public static function afterLogout(Request $request): Response
    {
        $pageflow = strtolower((string) ($request->header('X-Pageflow') ?? '')) === 'true';

        if (!$pageflow && $request->expectsJson()) {
            return Response::noContent();
        }

        $target = self::localPath($request->input('redirectTo'))
            ?? self::localPath($request->header('referer'))
            ?? '/';

        return $pageflow
            ? Response::json([], 409, ['X-Pageflow-Location' => $target])
            : Response::redirect($target, 303);
    }

    /** "/path?query" of a URL or path, or null — never a scheme, host or '//' prefix. */
    private static function localPath(mixed $url): ?string
    {
        if (!is_string($url) || $url === '') {
            return null;
        }

        $path = parse_url($url, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return null;
        }

        // Collapse '//evil.test' and '/\evil.test' into a plain local path.
        $path  = '/' . ltrim(str_replace('\\', '/', $path), '/');
        $query = parse_url($url, PHP_URL_QUERY);

        return is_string($query) && $query !== '' ? $path . '?' . $query : $path;
    }

    public function me(): Response
    {
        // Reflects HOWEVER the request is authenticated (session OR a verified
        // token attached by the SecurityGateway), so read the request Identity.
        $identity = $this->identity();
        if ($identity->isGuest()) {
            return Response::unauthorized('Not authenticated.');
        }

        return $this->ok([
            'userId'      => $identity->userId,
            'username'    => $identity->username,
            'email'       => $identity->email,
            'fullName'    => $identity->fullName,
            'tenantId'    => $identity->tenantId,
            'roles'       => $identity->roles,
            'permissions' => $identity->permissions,
            'via'         => $identity->tokenType,
            'emailVerified' => $this->emailVerified($identity->userId),
        ]);
    }

    // ── Device sessions ("see & sign out my devices") ───────────────────────────

    public function sessions(): Response
    {
        if ($this->devices === null) {
            return $this->ok(['sessions' => []]);
        }

        return $this->ok([
            'sessions' => $this->devices->listDevices($this->identity()->userId, $this->guardSession()),
        ]);
    }

    public function revokeSession(string $id): Response
    {
        if ($this->devices === null || !$this->devices->revokeById($this->identity()->userId, $id)) {
            return $this->notFound('No such session.');
        }

        return $this->noContent();
    }

    public function logoutOtherDevices(): Response
    {
        $password = (string) $this->resolveRequest()->input('password');
        if ($password === '') {
            return $this->unprocessable(['password' => 'Your current password is required.']);
        }

        // Guard re-verifies the password, revokes every OTHER device's session,
        // and rotates the remember token (reissuing this device's cookie).
        $user = $this->auth('web')->logoutOtherDevices($password);
        if ($user === null) {
            return Response::unauthorized('Password confirmation failed.');
        }

        return $this->ok(['message' => 'Signed out of all other devices.']);
    }

    // ── Internals ───────────────────────────────────────────────────────────────

    /**
     * Credential map: the identifier is offered under every lookup field the
     * ModelUserProvider tries (identifier/email/username), so a single input
     * works whether the user typed an email or a username.
     *
     * @return array<string,string>
     */
    private function credentials(string $identifier, string $password): array
    {
        return [
            'identifier' => $identifier,
            'email'      => $identifier,
            'username'   => $identifier,
            'password'   => $password,
        ];
    }

    /** @return array<string,string> */
    private function shape(?Authenticatable $user): array
    {
        if ($user === null) {
            return [];
        }

        $id = (string) $user->getAuthIdentifier();

        return [
            'id'            => $id,
            'email'         => $user->getEmail(),
            'username'      => $user->getUsername(),
            'emailVerified' => $this->emailVerified($id),
        ];
    }

    /**
     * Is this account's address confirmed? Drives the "verify your email"
     * banner — advisory UI, not a gate.
     *
     * Unknown (no User service bound) answers TRUE, and the asymmetry is
     * deliberate: this value only decides whether to NAG, so guessing "not
     * verified" would show every user of a deployment without the User plugin a
     * banner they can never dismiss. Enforcement is a separate decision made by
     * RequireVerifiedEmailStage, which fails the other way — it refuses when it
     * cannot tell. Advisory defaults open, enforcement defaults closed.
     */
    private function emailVerified(string $userId): bool
    {
        if ($this->users === null || $userId === '') {
            return true;
        }

        // isAuth: true skips find()'s requireSelfOrPermission() check. It has to:
        // on the login path this runs BEFORE the request Identity exists — the
        // Identity was resolved at SecurityStage, when the caller was still a
        // guest — so the authorized read would throw `user.unauthenticated` and
        // turn a successful sign-in into a 403. This is an auth-internal read of
        // the account that just authenticated, which is exactly what the flag is
        // for.
        return $this->users->find($userId, false, true)?->emailVerified ?? true;
    }

    /** The active session store, for flagging the caller's own device in listDevices(). */
    private function guardSession(): ?\AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort
    {
        $container = $this->resolveRequest()->container();

        return $container !== null && $container->has(\AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort::class)
            ? $container->make(\AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort::class)
            : null;
    }
}
