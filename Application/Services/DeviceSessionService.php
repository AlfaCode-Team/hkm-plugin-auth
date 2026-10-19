<?php

declare(strict_types=1);

namespace Plugins\Auth\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Database\TransactionManager;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\SessionPort;
use Plugins\Auth\Domain\ValueObjects\Recaller;
use Plugins\Auth\Infrastructure\Persistence\DeviceSessionRepository;

/**
 * DeviceSessionService — server-side session security for stateful logins.
 *
 * The GDA port of the old __DEV__ SessionDriver's two hardening features:
 *
 *  1. FINGERPRINT — at login a device fingerprint is stored in the session
 *     (SHA-256 of the client-supplied header when present, else of ip|user-agent).
 *     Every later resolution must reproduce it (hash_equals) or the session is
 *     treated as hijacked and torn down.
 *
 *  2. DEVICE REGISTRY — every login opens a row in `auth_sessions` and stores the
 *     raw token in the PHP session. Each resolution validates the row (revoked or
 *     expired ⇒ logout even though the browser cookie is still live) and slides
 *     its expiry forward. This is what makes "list my devices" / "sign out other
 *     devices" real.
 *
 *  3. PER-DEVICE REMEMBER-ME — a remembered sign-in stores the hash of that
 *     device's own remember token on its row (`remember_hash`), and the cookie
 *     names the row: `d:<session id>|<token>`. Using the cookie RESUMES that
 *     same row with fresh secrets ({@see resume()}) instead of opening a new
 *     one, and touches no other device. Revoking the row ends its remember-me.
 *
 * HOW LONG A ROW LIVES — the row is "a signed-in device", so it lasts exactly
 * as long as that device can stay signed in:
 *
 *   remembered      `ttl_days` (30), rolling: slides a full TTL once inside the
 *                   last `refresh_days`.
 *   not remembered  the session's own lifetime (`SESSION_LIFETIME`) plus one
 *                   touch interval, sliding on each (rate-limited) touch. Before
 *                   this, such a row was given 30 days, so every sign-in that
 *                   simply lapsed stayed "live" in the device list for a month.
 *
 * One orchestration surface so SessionAuthController, StatefulSessionGuard and
 * SessionAuthStage all share identical semantics.
 */
final class DeviceSessionService
{
    /** Session attribute keys (alongside AuthService::SESSION_*). */
    public const SESSION_DEVICE_TOKEN = 'auth.device_token';
    public const SESSION_FINGERPRINT  = 'auth.fingerprint';

    /** Skip the last-seen write when the row was stamped this recently. */
    private const TOUCH_INTERVAL_SECONDS = 300;

    public function __construct(
        private readonly DeviceSessionRepository $sessions,
        private readonly int $ttlDays = 30,
        private readonly int $refreshDays = 7,
        private readonly string $fingerprintHeader = 'X-Client-Fingerprint',
        private readonly ?TransactionManager $transaction = null, // central-connection tx
        /** Lifetime of a NOT remembered device: the session's own (SESSION_LIFETIME). */
        private readonly int $sessionTtlSeconds = 7200,
    ) {
    }

    // ── Fingerprint ─────────────────────────────────────────────────────────────

    /**
     * Compute the device fingerprint for a request. A client-supplied header
     * (e.g. FingerprintJS) wins; otherwise ip|user-agent. Always SHA-256 hashed
     * so raw client characteristics never persist.
     */
    public function fingerprint(Request $request): string
    {
        $client = (string) ($request->header($this->fingerprintHeader) ?? '');
        if ($client !== '') {
            return hash('sha256', $client);
        }

        $ip = (string) ($request->getClientIp() ?? '0.0.0.0');
        $ua = (string) ($request->header('User-Agent') ?? '');

        return hash('sha256', $ip . '|' . $ua);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────────

    /**
     * Bind the freshly-authenticated session to this device: store the
     * fingerprint and open a device-session row. Call right after
     * AuthService::startSession().
     *
     * A device row this session already carried (a sign-in over an earlier
     * one in the same browser) is closed first, so one browser is one row.
     *
     * With `$remember`, the row gets its own remember-me token and the cookie
     * to queue is returned. Null when not remembered — or when this database
     * has not run the `remember_hash` migration yet, in which case the caller
     * falls back to the legacy per-user token.
     */
    public function establish(SessionPort $session, Request $request, string $userId, bool $remember = false): ?Recaller
    {
        $previous = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        if ($previous !== '') {
            $this->transactional(fn () => $this->sessions->revokeByHash(hash('sha256', $previous)));
        }

        $session->put(self::SESSION_FINGERPRINT, $this->fingerprint($request));

        $opened = $this->open($request, $userId, $remember);
        $session->put(self::SESSION_DEVICE_TOKEN, $opened['token']);

        return $opened['recaller'];
    }

    /**
     * Open a device-session row and return its public id + RAW token (the only
     * time the raw token exists outside the PHP session), and the remember-me
     * cookie when one was asked for and could be stored.
     *
     * @return array{id:string,token:string,recaller:?Recaller}
     */
    public function open(Request $request, string $userId, bool $remember = false): array
    {
        $sessionId     = bin2hex(random_bytes(16));
        $token         = bin2hex(random_bytes(32));
        $rememberToken = $remember && $this->sessions->remembersPerDevice() ? bin2hex(random_bytes(32)) : null;

        $stored = $this->transactional(fn (): bool => $this->sessions->insert(
            sessionId:    $sessionId,
            userId:       $userId,
            tokenHash:    hash('sha256', $token),
            fingerprint:  $this->fingerprint($request),
            ip:           $request->getClientIp(),
            userAgent:    $request->header('User-Agent'),
            expiresAt:    $this->expiry($rememberToken !== null),
            rememberHash: $rememberToken !== null ? hash('sha256', $rememberToken) : null,
        ));

        return [
            'id'       => $sessionId,
            'token'    => $token,
            'recaller' => $stored && $rememberToken !== null ? Recaller::forDevice($sessionId, $rememberToken) : null,
        ];
    }

    /**
     * Sign a remembered device back in from its per-device cookie, on the SAME
     * row: new session token, new remember token, this request's fingerprint,
     * IP and agent, a fresh expiry. The new session token and fingerprint are
     * written into `$session`; call it after the session was (re)started.
     *
     * Returns the user to sign in and the cookie that replaces the one used,
     * or null when the cookie names no live remembered row, its token does not
     * match, or another request already used this cookie value (the swap is a
     * compare-and-swap on the old hash, so a cookie resumes a device once).
     *
     * No fingerprint check: a remembered device comes back days later from
     * another network, which is the point of remembering it. The row is
     * re-bound to where it is now.
     *
     * @return array{userId:string,recaller:Recaller}|null
     */
    public function resume(SessionPort $session, Request $request, Recaller $recaller): ?array
    {
        if (!$recaller->valid() || !$recaller->isDevice()) {
            return null;
        }

        $row = $this->sessions->findActiveBySessionId($recaller->deviceSessionId());
        $stored = is_array($row) ? ($row['remember_hash'] ?? null) : null;
        if (!is_string($stored) || $stored === '' || !hash_equals($stored, hash('sha256', $recaller->token()))) {
            return null;
        }

        if (new \DateTimeImmutable((string) $row['expires_at']) <= new \DateTimeImmutable()) {
            return null;
        }

        $sessionId     = (string) $row['session_id'];
        $token         = bin2hex(random_bytes(32));
        $rememberToken = bin2hex(random_bytes(32));
        $fingerprint   = $this->fingerprint($request);

        $swapped = $this->transactional(fn (): bool => $this->sessions->resume(
            sessionId:       $sessionId,
            oldRememberHash: $stored,
            tokenHash:       hash('sha256', $token),
            rememberHash:    hash('sha256', $rememberToken),
            fingerprint:     $fingerprint,
            ip:              $request->getClientIp(),
            userAgent:       $request->header('User-Agent'),
            expiresAt:       $this->expiry(true),
        ));
        if (!$swapped) {
            return null;
        }

        $session->put(self::SESSION_FINGERPRINT, $fingerprint);
        $session->put(self::SESSION_DEVICE_TOKEN, $token);

        return ['userId' => (string) $row['user_id'], 'recaller' => Recaller::forDevice($sessionId, $rememberToken)];
    }

    /**
     * New remember token for THIS device, when it is remembered — after "sign
     * out other devices", so a copy of this device's cookie taken before stops
     * working too. Null when this device is not remembered (it does not become
     * remembered by asking) or the database cannot store it.
     */
    public function rotateRemember(SessionPort $session): ?Recaller
    {
        $token = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        $row   = $token !== '' ? $this->sessions->findActiveByHash(hash('sha256', $token)) : null;
        if ($row === null || ($row['remember_hash'] ?? null) === null) {
            return null;
        }

        $sessionId     = (string) $row['session_id'];
        $rememberToken = bin2hex(random_bytes(32));
        $changed = $this->transactional(fn (): bool => $this->sessions->setRememberHash(
            $sessionId,
            hash('sha256', $rememberToken),
            $this->expiry(true),
        ));

        return $changed ? Recaller::forDevice($sessionId, $rememberToken) : null;
    }

    /**
     * Verify that the session still belongs to this device and is still live
     * server-side. True when valid; false ⇒ the caller MUST tear the session down.
     *
     * Backward-compatible: a session with no stored fingerprint / device token
     * (opened before this feature, or a bare startSession()) passes.
     */
    public function verify(SessionPort $session, Request $request): bool
    {
        $stored = (string) $session->get(self::SESSION_FINGERPRINT, '');
        if ($stored !== '' && !hash_equals($stored, $this->fingerprint($request))) {
            return false;
        }

        $token = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        if ($token === '') {
            return true;
        }

        $row = $this->sessions->findActiveByHash(hash('sha256', $token));
        if ($row === null) {
            return false;
        }

        $now       = new \DateTimeImmutable();
        $expiresAt = new \DateTimeImmutable((string) $row['expires_at']);
        if ($expiresAt <= $now) {
            return false;
        }

        $remembered = ($row['remember_hash'] ?? null) !== null;
        $stale      = $this->lastSeenIsStale($row['last_seen_at'] ?? null, $now);

        if ($remembered) {
            // Rolling refresh: once inside the refresh window, slide the expiry
            // a full TTL forward. Otherwise just stamp last-seen (rate-limited).
            $refreshFrom = $expiresAt->sub(new \DateInterval('P' . max(1, $this->refreshDays) . 'D'));
            if ($now >= $refreshFrom) {
                $this->sessions->touch((string) $row['session_id'], $this->expiry(true));
            } elseif ($stale) {
                $this->sessions->touch((string) $row['session_id']);
            }
        } elseif ($stale) {
            // Not remembered: the row lives as long as the session can, so it
            // slides with the same (rate-limited) touch that stamps last-seen —
            // no write beyond the one already made. A pre-migration 30-day row
            // converges to this on its first touch.
            $this->sessions->touch((string) $row['session_id'], $this->expiry(false));
        }

        return true;
    }

    /**
     * Drop a session that failed verify(): forget this device's secrets, and
     * revoke its row unless the device is REMEMBERED.
     *
     * A remembered row survives so its own cookie can resume it (and re-bind
     * it to the new network) — otherwise every IP change on a phone would
     * end "keep me signed in". Whoever holds only a session cookie gains
     * nothing from that: resuming needs the remember cookie. A revoked or
     * expired row was refused for that reason, so leaving it is no change.
     */
    public function release(SessionPort $session): void
    {
        $token = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        $row   = $token !== '' ? $this->sessions->findActiveByHash(hash('sha256', $token)) : null;

        if ($row !== null && ($row['remember_hash'] ?? null) !== null) {
            $session->forget(self::SESSION_DEVICE_TOKEN);
            $session->forget(self::SESSION_FINGERPRINT);

            return;
        }

        $this->teardown($session);
    }

    /** Revoke this device's server-side session (logout). */
    public function teardown(SessionPort $session): void
    {
        $token = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        if ($token !== '') {
            $this->transactional(fn () => $this->sessions->revokeByHash(hash('sha256', $token)));
        }

        $session->forget(self::SESSION_DEVICE_TOKEN);
        $session->forget(self::SESSION_FINGERPRINT);
    }

    /**
     * Revoke every OTHER device session for the user, keeping the current
     * device's row alive (old logoutOtherDevices semantics). Returns the number
     * of sessions revoked.
     */
    public function revokeOthers(SessionPort $session, Request $request, string $userId): int
    {
        $token     = (string) $session->get(self::SESSION_DEVICE_TOKEN, '');
        $currentId = null;

        if ($token !== '') {
            $row       = $this->sessions->findActiveByHash(hash('sha256', $token));
            $currentId = $row !== null ? (string) $row['session_id'] : null;
        }

        // One transaction: the sweep and the replacement row commit together,
        // so a failure cannot leave the user with every device signed out AND
        // no registered session (the shared manager nests establish → open).
        return $this->transactional(function () use ($session, $request, $userId, $currentId): int {
            $revoked = $this->sessions->revokeAllForUser($userId, $currentId);

            // No live row for this device (pre-feature session) — open one so
            // the user keeps a registered session after the sweep.
            if ($currentId === null) {
                $this->establish($session, $request, $userId);
            }

            return $revoked;
        });
    }

    // ── Device listing / targeted revocation ────────────────────────────────────

    /**
     * Active sessions for a user, flagging the caller's own device.
     *
     * @return list<array<string,mixed>>
     */
    public function listDevices(string $userId, ?SessionPort $session = null): array
    {
        $currentId = null;
        $token     = $session !== null ? (string) $session->get(self::SESSION_DEVICE_TOKEN, '') : '';
        if ($token !== '') {
            $row       = $this->sessions->findActiveByHash(hash('sha256', $token));
            $currentId = $row !== null ? (string) $row['session_id'] : null;
        }

        // A row that was not remembered and has not been seen for longer than
        // a session can last belongs to a sign-in that simply lapsed. Rows
        // opened before rows were given the session's lifetime still carry 30
        // days, so they are left out here rather than listed as live devices.
        $lapsedBefore = (new \DateTimeImmutable())->getTimestamp() - $this->sessionTtlSeconds - self::TOUCH_INTERVAL_SECONDS;
        $live = array_filter(
            $this->sessions->listActiveForUser($userId),
            static fn (array $row): bool => $row['remembered'] || $row['session_id'] === $currentId
                || (is_string($row['last_seen_at']) && strtotime($row['last_seen_at']) >= $lapsedBefore),
        );

        return array_values(array_map(static fn (array $row): array => [
            'id'         => $row['session_id'],
            'ip'         => $row['ip'],
            'userAgent'  => $row['user_agent'],
            'lastSeen'   => $row['last_seen_at'],
            'createdAt'  => $row['created_at'],
            'expiresAt'  => $row['expires_at'],
            'current'    => $row['session_id'] === $currentId,
            'remembered' => $row['remembered'],
        ], $live));
    }

    /** Revoke one of the user's sessions by public id. True when it existed. */
    public function revokeById(string $userId, string $sessionId): bool
    {
        return $this->transactional(fn (): bool => $this->sessions->revokeForUser($userId, $sessionId));
    }

    /**
     * Revoke EVERY session for a user, the caller's own included.
     *
     * Unlike revokeOthers(), this keeps no session alive and needs no SessionPort
     * — it is for credential-recovery paths (password reset) where the request is
     * unauthenticated and no existing session can be trusted: whoever knew the
     * old password may still be signed in somewhere.
     */
    public function revokeAll(string $userId): int
    {
        return $this->transactional(fn (): int => $this->sessions->revokeAllForUser($userId, null));
    }

    // ── Internals ───────────────────────────────────────────────────────────────

    /**
     * Bracket a unit of work in a transaction on the central auth connection.
     * Nesting-aware (TransactionManager), and a straight pass-through when no
     * manager was injected (unit tests with in-memory stores).
     */
    private function transactional(callable $work): mixed
    {
        if ($this->transaction === null) {
            return $work();
        }

        $this->transaction->begin();
        try {
            $result = $work();
            $this->transaction->commit();

            return $result;
        } catch (\Throwable $e) {
            $this->transaction->rollback();
            throw $e;
        }
    }

    /**
     * When a row expires if nothing extends it: `ttl_days` for a remembered
     * device; otherwise the session's lifetime plus one touch interval, so the
     * row never dies before the session it records (it slides only on the
     * rate-limited touch, up to TOUCH_INTERVAL_SECONDS behind the last request).
     */
    private function expiry(bool $remembered = true): \DateTimeImmutable
    {
        $now = new \DateTimeImmutable();

        return $remembered
            ? $now->add(new \DateInterval('P' . max(1, $this->ttlDays) . 'D'))
            : $now->add(new \DateInterval('PT' . (max(60, $this->sessionTtlSeconds) + self::TOUCH_INTERVAL_SECONDS) . 'S'));
    }

    private function lastSeenIsStale(mixed $lastSeenAt, \DateTimeImmutable $now): bool
    {
        if (!is_string($lastSeenAt) || $lastSeenAt === '') {
            return true;
        }

        try {
            $seen = new \DateTimeImmutable($lastSeenAt);
        } catch (\Exception) {
            return true;
        }

        return ($now->getTimestamp() - $seen->getTimestamp()) >= self::TOUCH_INTERVAL_SECONDS;
    }
}
