<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\Lock;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Security\JwtAuthLayer;

/**
 * Revoking every token a user holds, without stopping them signing back in.
 *
 * An access token in a client's memory cannot be un-issued, and the issuer does
 * not keep every `jti`, so a ban / role change / lost device records the moment
 * the user's authority changed. Tokens minted before it die on their next
 * request; a token minted after it — the fresh sign-in — does not.
 *
 * The two cases that matter most are the ones that are silent when wrong: a
 * fresh sign-in that gets killed by the cutoff (the user can never get back in),
 * and a cache outage that signs out the entire field.
 */
#[CoversClass(JwtAuthLayer::class)]
final class JwtUserRevocationTest extends TestCase
{
    private const SECRET = 'a-test-secret-of-sufficient-length-32+';

    private function token(int $issuedAt, string $sub = 'user-1', bool $withIat = true): string
    {
        $claims = ['sub' => $sub, 'exp' => time() + 300];
        if ($withIat) {
            $claims['iat'] = $issuedAt;
        }

        return JWT::encode($claims, self::SECRET, 'HS256');
    }

    private function layer(?CachePort $cache): JwtAuthLayer
    {
        return new JwtAuthLayer(secret: self::SECRET, algo: 'HS256', revocations: $cache);
    }

    private function check(JwtAuthLayer $layer, string $token): \AlfacodeTeam\PhpServicePlatform\Kernel\Security\SecurityVerdict
    {
        return $layer->check(
            Request::build(method: 'GET', path: '/x')->withHeader('Authorization', 'Bearer ' . $token),
        );
    }

    public function test_a_token_minted_before_the_cutoff_is_refused(): void
    {
        $cache = new ArrayCache([JwtAuthLayer::userRevocationKey('user-1') => time()]);

        $verdict = $this->check($this->layer($cache), $this->token(time() - 60));

        self::assertFalse($verdict->isAllowed());
        self::assertSame(401, $verdict->statusCode());
    }

    /**
     * The whole point of a cutoff rather than a deny-list: revoking a user's
     * access must not stop them signing back in.
     */
    public function test_a_token_minted_after_the_cutoff_still_works(): void
    {
        $cache = new ArrayCache([JwtAuthLayer::userRevocationKey('user-1') => time() - 60]);

        $verdict = $this->check($this->layer($cache), $this->token(time()));

        self::assertTrue($verdict->isAllowed(), 'a fresh sign-in must survive the revocation');
        self::assertSame('user-1', $verdict->identity()?->userId);
    }

    /** Another user's cutoff is none of this user's business. */
    public function test_a_cutoff_applies_only_to_its_own_user(): void
    {
        $cache = new ArrayCache([JwtAuthLayer::userRevocationKey('someone-else') => time()]);

        $verdict = $this->check($this->layer($cache), $this->token(time() - 60));

        self::assertTrue($verdict->isAllowed());
    }

    /**
     * A token that cannot be shown to post-date the cutoff is refused rather
     * than given the benefit of the doubt — the cutoff exists precisely because
     * this user's outstanding tokens are not to be honoured.
     */
    public function test_a_token_without_an_iat_cannot_outlive_a_cutoff(): void
    {
        $cache = new ArrayCache([JwtAuthLayer::userRevocationKey('user-1') => time()]);

        $verdict = $this->check($this->layer($cache), $this->token(0, withIat: false));

        self::assertFalse($verdict->isAllowed());
    }

    /** With no cutoff recorded, nothing changes for anybody. */
    public function test_no_cutoff_means_no_effect(): void
    {
        $verdict = $this->check($this->layer(new ArrayCache()), $this->token(time() - 3600));

        self::assertTrue($verdict->isAllowed());
    }

    /**
     * FAIL OPEN. Failing closed would sign every user out the moment the cache
     * blinked — a far larger harm than honouring a cryptographically valid
     * token for the rest of its (short) life.
     */
    public function test_a_cache_outage_does_not_sign_everybody_out(): void
    {
        $verdict = $this->check($this->layer(new ThrowingCache()), $this->token(time() - 60));

        self::assertTrue($verdict->isAllowed(), 'a cache outage must not deny a valid token');
    }

    /** No cache bound at all: the feature is simply inert. */
    public function test_without_a_cache_the_check_is_skipped(): void
    {
        $verdict = $this->check($this->layer(null), $this->token(time() - 3600));

        self::assertTrue($verdict->isAllowed());
    }
}

/** @internal */
class ArrayCache implements CachePort
{
    /** @param array<string, mixed> $items */
    public function __construct(private array $items = []) {}

    public function get(string $key): mixed { return $this->items[$key] ?? null; }
    public function set(string $key, mixed $value, ?int $ttl = null): bool { $this->items[$key] = $value; return true; }
    public function delete(string $key): bool { unset($this->items[$key]); return true; }
    public function has(string $key): bool { return array_key_exists($key, $this->items); }
    public function remember(string $key, int $ttl, callable $callback): mixed { return $this->items[$key] ??= $callback(); }
    public function increment(string $key, int $by = 1): int { return $this->items[$key] = (int) ($this->items[$key] ?? 0) + $by; }
    public function deletePattern(string $pattern): int { return 0; }
    public function flush(): bool { $this->items = []; return true; }
    public function lock(string $name, int $seconds = 0, ?string $owner = null): Lock { throw new \LogicException('unused'); }
    public function restoreLock(string $name, string $owner): Lock { throw new \LogicException('unused'); }
}

/** @internal A cache that is down. */
final class ThrowingCache extends ArrayCache
{
    public function get(string $key): mixed { throw new \RuntimeException('cache is down'); }
    public function has(string $key): bool { throw new \RuntimeException('cache is down'); }
}
