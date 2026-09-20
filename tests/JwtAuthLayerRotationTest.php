<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Security\JwtAuthLayer;

/**
 * The three capabilities an asymmetric, browser-facing authorization server
 * needs from this layer: verify by `kid` across a key rotation, read the token
 * from a cookie when a navigation cannot carry a header, and answer a bad token
 * as a guest when the application refuses in its own error shape.
 *
 * Each is OPT-IN. The default construction is asserted to behave exactly as it
 * did before they existed, because this layer sits in front of every request in
 * every application using the plugin.
 */
#[CoversClass(JwtAuthLayer::class)]
final class JwtAuthLayerRotationTest extends TestCase
{
    /** @var array{0: string, 1: string} [privatePem, publicPem] */
    private static array $current;
    /** @var array{0: string, 1: string} */
    private static array $retired;

    public static function setUpBeforeClass(): void
    {
        self::$current = self::keypair();
        self::$retired = self::keypair();
    }

    /** @return array{0: string, 1: string} */
    private static function keypair(): array
    {
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($res, 'openssl is required for RS256 cover');

        openssl_pkey_export($res, $private);
        $public = (string) openssl_pkey_get_details($res)['key'];

        return [(string) $private, $public];
    }

    private function token(string $privatePem, string $kid, array $claims = []): string
    {
        return JWT::encode(
            $claims + ['sub' => 'user-1', 'exp' => time() + 300],
            $privatePem,
            'RS256',
            $kid,
        );
    }

    /** @param array<string, string> $cookies */
    private function request(array $cookies = []): Request
    {
        return Request::build(method: 'GET', path: '/x', cookies: $cookies);
    }

    /**
     * The point of the rotation set: a token signed by the PREVIOUS key still
     * verifies. Holding only the current key signs out every user at once the
     * moment the key turns over.
     */
    public function test_a_token_signed_by_a_retired_key_still_verifies(): void
    {
        $layer = new JwtAuthLayer(
            secret: '',
            algo: 'RS256',
            keys: ['current' => self::$current[1], 'retired' => self::$retired[1]],
        );

        foreach (['current' => self::$current[0], 'retired' => self::$retired[0]] as $kid => $private) {
            $verdict = $layer->check(
                $this->request()->withHeader('Authorization', 'Bearer ' . $this->token($private, $kid)),
            );

            self::assertTrue($verdict->isAllowed(), "a token signed by the [{$kid}] key must verify");
            self::assertSame('user-1', $verdict->identity()?->userId);
        }
    }

    /** A key that is not in the set cannot verify, however valid its signature. */
    public function test_a_token_signed_by_an_unknown_key_is_refused(): void
    {
        [$strangerPrivate] = self::keypair();

        $layer = new JwtAuthLayer(
            secret: '',
            algo: 'RS256',
            keys: ['current' => self::$current[1]],
        );

        $verdict = $layer->check(
            $this->request()->withHeader('Authorization', 'Bearer ' . $this->token($strangerPrivate, 'stranger')),
        );

        self::assertFalse($verdict->isAllowed());
        self::assertSame(401, $verdict->statusCode());
    }

    public function test_the_cookie_is_read_only_when_no_bearer_is_present(): void
    {
        $layer = new JwtAuthLayer(
            secret: '',
            algo: 'RS256',
            keys: ['current' => self::$current[1]],
            cookie: 'console_token',
        );

        $good = $this->token(self::$current[0], 'current');

        $fromCookie = $layer->check($this->request(['console_token' => $good]));
        self::assertTrue($fromCookie->isAllowed(), 'a navigation carries the token in its cookie');
        self::assertSame('user-1', $fromCookie->identity()?->userId);

        // The header is attached deliberately; the cookie is attached by the
        // browser on the caller's behalf. The deliberate one wins.
        $bothPresent = $layer->check(
            $this->request(['console_token' => $good])
                ->withHeader('Authorization', 'Bearer not.a.token'),
        );
        self::assertFalse($bothPresent->isAllowed(), 'the header must win, and it is garbage');
    }

    /**
     * Guest mode: the layer resolves an identity when it can and otherwise
     * steps aside, so the application refuses in its OWN envelope. A client
     * that cannot parse the kernel's shape shows its user nothing at all.
     */
    public function test_guest_mode_lets_a_bad_token_through_without_an_identity(): void
    {
        $layer = new JwtAuthLayer(
            secret: '',
            algo: 'RS256',
            keys: ['current' => self::$current[1]],
            denyInvalid: false,
        );

        $verdict = $layer->check(
            $this->request()->withHeader('Authorization', 'Bearer not.a.token'),
        );

        self::assertTrue($verdict->isAllowed(), 'guest mode never denies');
        self::assertTrue(
            $verdict->identity() === null || $verdict->identity()->isGuest(),
            'a bad token must not resolve to a signed-in identity',
        );

        // It still resolves a GOOD one — guest mode is about refusal, not about
        // switching authentication off.
        $good = $layer->check(
            $this->request()->withHeader(
                'Authorization',
                'Bearer ' . $this->token(self::$current[0], 'current'),
            ),
        );
        self::assertSame('user-1', $good->identity()?->userId);
    }

    /** Every new argument is opt-in: the default construction is unchanged. */
    public function test_the_default_construction_still_denies_and_ignores_cookies(): void
    {
        $layer = new JwtAuthLayer(secret: str_repeat('k', 40), algo: 'HS256');

        $bad = $layer->check($this->request()->withHeader('Authorization', 'Bearer not.a.token'));
        self::assertFalse($bad->isAllowed(), 'the default is still deny-on-invalid');
        self::assertSame(401, $bad->statusCode());

        $anonymous = $layer->check($this->request());
        self::assertTrue($anonymous->isAllowed(), 'no token at all is still an anonymous pass-through');

        $cookieOnly = $layer->check($this->request(['console_token' => 'whatever']));
        self::assertTrue($cookieOnly->isAllowed(), 'a cookie is ignored unless a name was configured');
        self::assertTrue(
            $cookieOnly->identity() === null || $cookieOnly->identity()->isGuest(),
            'and it certainly does not authenticate anyone',
        );
    }
}
