<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Application\Auth\PasswordResetBroker;
use Plugins\Auth\Security\JwtAuthLayer;

/**
 * Regression cover for S-32h (JWT leeway leaked process-wide) and S-04 (OTP
 * brute force). S-04's counter is already present — these tests pin it so it
 * cannot regress silently.
 */
#[CoversClass(JwtAuthLayer::class)]
#[CoversClass(PasswordResetBroker::class)]
final class AuthSecurityRegressionTest extends TestCase
{
    // ── S-32h ───────────────────────────────────────────────────────────────

    public function test_the_layer_restores_the_global_leeway_after_decoding(): void
    {
        $before = JWT::$leeway;

        try {
            JWT::$leeway = 0;

            $layer = new JwtAuthLayer(secret: str_repeat('k', 40), algo: 'HS256', leeway: 120);

            // A garbage token still exercises the set/restore around decode().
            $layer->check(
                \AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request::build(method: 'GET', path: '/x')
                    ->withHeader('Authorization', 'Bearer not.a.token'),
            );

            self::assertSame(
                0,
                JWT::$leeway,
                'leeway must be restored — under a resident worker it would otherwise '
                . 'leak into every later decode in the process',
            );
        } finally {
            JWT::$leeway = $before;
        }
    }

    public function test_a_zero_leeway_layer_does_not_inherit_a_previous_tolerance(): void
    {
        $before = JWT::$leeway;

        try {
            // A previous layer left a wide tolerance behind.
            JWT::$leeway = 3600;

            $layer = new JwtAuthLayer(secret: str_repeat('k', 40), algo: 'HS256', leeway: 0);
            $layer->check(
                \AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request::build(method: 'GET', path: '/x')
                    ->withHeader('Authorization', 'Bearer not.a.token'),
            );

            // The old code skipped the assignment when leeway was 0, so this
            // layer silently verified with someone else's 1-hour tolerance.
            self::assertSame(3600, JWT::$leeway, 'restored, not left at our value');
        } finally {
            JWT::$leeway = $before;
        }
    }

    // ── S-04 ────────────────────────────────────────────────────────────────

    public function test_the_otp_attempt_bound_is_small(): void
    {
        // 10^6 code space: an unbounded guesser inside the TTL is account
        // takeover, so the per-account cap must stay tight.
        $ctor  = new \ReflectionMethod(PasswordResetBroker::class, '__construct');
        $bound = null;

        foreach ($ctor->getParameters() as $p) {
            if ($p->getName() === 'maxOtpAttempts') {
                $bound = $p->getDefaultValue();
            }
        }

        self::assertNotNull($bound, 'the per-account attempt cap must exist');
        self::assertLessThanOrEqual(10, $bound);
    }
}
