<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Controllers;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\MailPort;
use Plugins\Auth\Application\Ports\PasswordBroker;
use Project\Http\Controllers\ApiController;

/**
 * PasswordResetController — the old __DEV__ OTP forgot-password flow.
 *
 *   POST /auth/password/forgot     { email }              → 200 {} ALWAYS
 *   POST /auth/password/verify-otp { email, otp }         → 200 { resetToken } | 400
 *   POST /auth/password/reset      { email, token, password } → 200 {} | 400/422
 *
 * The forgot endpoint responds identically whether or not the account exists
 * (enumeration-safe). The 6-digit OTP is emailed via the OPTIONAL MailPort —
 * when no mailer is bound the flow still works for clients that receive the
 * code out-of-band (and the Array/Log transports capture it in dev).
 */
final class PasswordResetController extends ApiController
{
    private const GENERIC_FORGOT_MESSAGE =
        "If that email is registered, you'll receive a 6-digit code shortly. Check your inbox and spam folder.";

    /** Message for a caller that has run out of sends for this address. */
    private const CAPPED_FORGOT_MESSAGE =
        "You've requested several codes for this address already. Use the most recent one, or try again later.";

    /** Cache key prefixes for the send limiter — hashed address, never the address. */
    private const COOLDOWN_PREFIX = 'auth:pwreset:send:cool:';
    private const SENDS_PREFIX    = 'auth:pwreset:send:count:';

    public function __construct(
        private readonly PasswordBroker $broker,
        private readonly ?MailPort $mail = null,
        /**
         * Optional — the send limiter's store. Without it the endpoint keeps its
         * previous behaviour (the broker's own re-issue throttle still applies),
         * so a deployment with no cache degrades rather than breaking.
         */
        private readonly ?CachePort $cache = null,
    ) {
    }

    public function forgot(): Response
    {
        $email = mb_strtolower(trim((string) $this->resolveRequest()->input('email')));
        if ($email === '') {
            return $this->unprocessable(['email' => 'An email address is required.']);
        }

        // HOW MANY CODES ONE ADDRESS MAY BE SENT.
        //
        // The route's throttle counts REQUESTS PER IP, which bounds the attacker
        // but not the victim: rotate IPs and one inbox still takes an unbounded
        // stream of codes, each one invalidating the last. The limiter below is
        // keyed on the ADDRESS, so the mailbox is what is protected:
        //
        //   • a cooldown between sends (default 60s), so "Resend" cannot be held
        //     down, and the client is told how long to wait;
        //   • a ceiling per window (default 5/hour), after which nothing is sent
        //     until the window rolls over.
        //
        // Both are keyed on the SUBMITTED address whether or not it belongs to
        // an account, so the timings are identical for a registered and an
        // unregistered address and the endpoint stays enumeration-safe.
        $limit = $this->sendAllowance($email);

        if ($limit['allowed']) {
            $sent = $this->broker->sendOtp($email);

            if ($sent !== null && $this->mail !== null) {
                try {
                    $this->mail->send(
                        $sent['email'],
                        'Your password reset code',
                        'auth::password-otp',
                        ['otp' => $sent['otp'], 'expiresMinutes' => 10],
                    );
                } catch (\Throwable) {
                    // Non-fatal — never leak delivery problems to the caller.
                }
            }
        }

        // Always 200 — never reveals whether an account exists. `retryAfter` is
        // how long until this address may be sent another code (0 = now), and
        // `remaining` how many are left in the window; both are facts about the
        // caller's own requests, so neither discloses anything about the account.
        return $this->ok([
            'message'    => $limit['capped'] ? self::CAPPED_FORGOT_MESSAGE : self::GENERIC_FORGOT_MESSAGE,
            'retryAfter' => $limit['retryAfter'],
            'remaining'  => $limit['remaining'],
        ]);
    }

    /**
     * An int setting, where an UNSET var takes the default but an explicit "0"
     * is honoured. `env(...) ?: $default` cannot express that — "0" is falsy, so
     * an operator disabling the cooldown would silently get the default back.
     */
    private function intSetting(string $key, int $default): int
    {
        $raw = env($key);

        return $raw === null || $raw === '' ? $default : (int) $raw;
    }

    /**
     * Decide whether this address may be sent a code now, and what to tell the
     * caller either way.
     *
     * @return array{allowed:bool, capped:bool, retryAfter:int, remaining:int}
     */
    private function sendAllowance(string $email): array
    {
        $max      = max(1, $this->intSetting('AUTH_OTP_MAX_SENDS', 5));
        $window   = max(60, $this->intSetting('AUTH_OTP_SEND_WINDOW', 3600));
        $cooldown = max(0, $this->intSetting('AUTH_OTP_SEND_COOLDOWN', 60));

        // No cache bound: fail OPEN. The broker still refuses a re-issue inside
        // its own throttle window, and the per-IP route throttle still applies —
        // refusing every reset instead would be the worse failure.
        if (!$this->cache instanceof CachePort) {
            return ['allowed' => true, 'capped' => false, 'retryAfter' => 0, 'remaining' => $max];
        }

        $key = hash('sha256', $email);

        // Cooldown first: it is the cheaper check and the common one.
        if ($cooldown > 0 && $this->cache->has(self::COOLDOWN_PREFIX . $key)) {
            return [
                'allowed'   => false,
                'capped'    => false,
                'retryAfter' => $cooldown,
                'remaining' => max(0, $max - (int) ($this->cache->get(self::SENDS_PREFIX . $key) ?? 0)),
            ];
        }

        $sends = (int) ($this->cache->get(self::SENDS_PREFIX . $key) ?? 0);
        if ($sends >= $max) {
            return ['allowed' => false, 'capped' => true, 'retryAfter' => $window, 'remaining' => 0];
        }

        // Count the send BEFORE it happens: a mail transport that hangs or
        // throws must still consume the allowance, or the limit is bypassable
        // by whatever makes delivery fail.
        //
        // set() on the first send and increment() after, because increment()
        // carries no TTL — a counter created by increment() alone would never
        // expire and would lock the address out permanently.
        $sends === 0
            ? $this->cache->set(self::SENDS_PREFIX . $key, 1, $window)
            : $this->cache->increment(self::SENDS_PREFIX . $key);

        if ($cooldown > 0) {
            $this->cache->set(self::COOLDOWN_PREFIX . $key, 1, $cooldown);
        }

        return [
            'allowed'   => true,
            'capped'    => false,
            'retryAfter' => $cooldown,
            'remaining' => max(0, $max - ($sends + 1)),
        ];
    }

    public function verifyOtp(): Response
    {
        $request = $this->resolveRequest();
        $email = mb_strtolower(trim((string) $request->input('email')));
        $otp = trim((string) $request->input('otp'));

        if ($email === '' || !preg_match('/^\d{6}$/', $otp)) {
            return $this->unprocessable([
                'email' => $email === '' ? 'An email address is required.' : '',
                'otp' => 'The code must be exactly 6 digits.',
            ]);
        }

        $token = $this->broker->verifyOtp($email, $otp);
        if ($token === null) {
            return Response::json([
                'error' => [
                    'code' => 'auth.password.otp_invalid',
                    'message' => "That code doesn't match or has expired. Codes are valid for 10 minutes — request a fresh one.",
                ]
            ], 400);
        }

        return $this->ok(['resetToken' => $token]);
    }

    /** Hashing cost is attacker-controlled by length — cap it well below any DoS. */
    private const MAX_PASSWORD_BYTES = 4096;

    public function reset(): Response
    {
        $request  = $this->resolveRequest();
        $email    = mb_strtolower(trim((string) $request->input('email')));
        $token    = trim((string) $request->input('token'));
        $password = (string) $request->input('password');
        $confirm  = $request->input('password_confirmation');

        $errors = [];

        if ($email === '') {
            $errors['email'] = 'An email address is required.';
        }
        if ($token === '') {
            $errors['token'] = 'Your reset session is missing — request a new code.';
        }

        if (\strlen($password) < 8) {
            $errors['password'] = 'Password must be at least 8 characters.';
        } elseif (\strlen($password) > self::MAX_PASSWORD_BYTES) {
            // Unbounded input would let anyone burn CPU in the hasher at will.
            $errors['password'] = 'Password must be at most ' . self::MAX_PASSWORD_BYTES . ' characters.';
        } elseif (str_contains($password, "\0")) {
            // password_hash() throws on a NUL byte — reject it as input, not a 500.
            $errors['password'] = 'Password contains an invalid character.';
        } elseif (mb_strtolower($password) === $email && $email !== '') {
            $errors['password'] = 'Your password cannot be your email address.';
        }

        // Confirmation is enforced whenever the client sends it, so the browser
        // form's check cannot be skipped by posting the endpoint directly.
        if (!isset($errors['password']) && $confirm !== null && !hash_equals($password, (string) $confirm)) {
            $errors['password_confirmation'] = 'The two passwords do not match.';
        }

        if ($errors !== []) {
            return $this->unprocessable($errors);
        }

        if ($this->broker->reset($email, $token, $password) !== PasswordBroker::PASSWORD_RESET) {
            return Response::json(['error' => [
                'code'    => 'auth.password.reset_invalid',
                'message' => 'This reset session has already been used or has expired. Please start again.',
            ]], 400);
        }

        $this->notifyPasswordChanged($email, $request);

        return $this->ok(['message' => 'Your password has been updated. You can now sign in.']);
    }

    /**
     * Tell the account owner their password just changed.
     *
     * This is the account-takeover tripwire: when the reset was NOT them, this
     * mail is the only signal they get — so it goes out on every successful
     * reset, and carries no token and no login link.
     *
     * Best-effort: the password is already changed and the sessions already
     * swept by the time we get here, so a mail failure must never turn a
     * completed reset into an error the user would retry.
     */
    private function notifyPasswordChanged(string $email, Request $request): void
    {
        if ($this->mail === null) {
            return;
        }

        try {
            $this->mail->send(
                $email,
                'Your password was changed',
                'auth::password-changed',
                [
                    'email'     => $email,
                    'changedAt' => gmdate('D, d M Y H:i') . ' UTC',
                    // Kernel surface, not Symfony's — ip() already resolves the
                    // client address (honouring trusted proxies).
                    'ip'        => (string) ($request->ip() ?? ''),
                ],
            );
        } catch (\Throwable) {
            // Never surface delivery problems on a reset that already succeeded.
        }
    }
}
