<?php

declare(strict_types=1);

namespace Plugins\Auth\Security;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Contracts\SecurityLayerContract;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\SecurityVerdict;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Stateless JWT authentication layer.
 *
 * Fills the kernel's intended "AuthModule layer" slot: the kernel ships no
 * token validator, so this plugin provides one. Wire it in a project bootstrap:
 *
 *   ->withSecurity([
 *       new JwtAuthLayer(secret: env('JWT_SECRET'), algo: 'HS256'),
 *   ])
 *
 * Behaviour:
 *   - No Authorization header        -> allow as guest (public routes still work)
 *   - Valid Bearer token             -> allow with a resolved Identity
 *   - Malformed / invalid / expired  -> deny(401)
 *
 * Never throws — always returns a SecurityVerdict (GDA security rule).
 */
final class JwtAuthLayer implements SecurityLayerContract
{
    /**
     * @param string      $secret   HMAC secret (HS) or PEM public key (RS / ES).
     * @param string      $algo     Signing algorithm to accept (single algo — never trust the header `alg`).
     * @param string|null $issuer   When set, the `iss` claim MUST equal this value.
     * @param string|null $audience When set, the `aud` claim MUST contain this value.
     * @param int         $leeway   Clock-skew tolerance in seconds for exp/iat/nbf.
     * @param CachePort|null $revocations When set, the `jti` claim is checked against
     *        a deny-list so a token can be revoked before its natural expiry.
     */
    public function __construct(
        private readonly string $secret,
        private readonly string $algo = 'HS256',
        private readonly ?string $issuer = null,
        private readonly ?string $audience = null,
        private readonly int $leeway = 0,
        private readonly ?CachePort $revocations = null,
        /**
         * `kid` => key material, for a server that ROTATES its signing key.
         *
         * A token carries the `kid` of the key that signed it, so a verifier
         * holding only the current key rejects every token still in a handset's
         * memory the moment the key turns over — which signs out every user at
         * once rather than letting the old tokens expire on their own. Keep a
         * retired key here for at least the lifetime of the longest-lived token
         * it signed.
         *
         * With entries present the token's `kid` selects the key and a token
         * without one, or with an unknown one, is refused. Empty = the single
         * `$secret` verifies everything, exactly as before.
         *
         * @var array<string, string>
         */
        private readonly array $keys = [],
        /**
         * Cookie to read the token from when there is no `Authorization` header.
         *
         * A browser cannot attach a header to a plain navigation, so a web
         * console carrying the SAME token in an HttpOnly cookie would otherwise
         * need a second verifier and a second token format. The header still
         * WINS when both are present: a cookie is attached by the browser on the
         * caller's behalf, a header is attached deliberately.
         *
         * '' = bearer only.
         */
        private readonly string $cookie = '',
        /**
         * What a BAD token produces: `true` (default) denies 401 here, before
         * any module loads. `false` produces a GUEST identity and lets the
         * request continue to the route's own authorization filter.
         *
         * Guest mode exists for an application whose error envelope differs from
         * the kernel's — denying here returns the KERNEL's shape, and a client
         * that cannot parse it shows the user nothing at all. Such an app denies
         * in its own filter, in its own shape, and uses this layer only to
         * resolve an identity when one is present.
         *
         * It is NOT a way to leave a route unprotected: with `false`, something
         * downstream MUST reject the guest.
         */
        private readonly bool $denyInvalid = true,
    ) {
    }

    /** Deny-list cache key for a revoked token id. */
    public static function revocationKey(string $jti): string
    {
        return 'auth:jwt:revoked:' . $jti;
    }

    /**
     * Cache key holding the moment a user's AUTHORITY last changed.
     *
     * Every token minted before it is dead; one minted after it is not. That
     * distinction is the whole point — revoking a user's access must not also
     * stop them signing back in, which is what deny-listing them outright does.
     *
     * It is the answer to "the ban has to bite on the NEXT REQUEST": an access
     * token already in a client's memory cannot be un-issued, so a change of
     * role, of tenant, of device — or a ban — records a cutoff here instead and
     * every outstanding token fails its next verification.
     */
    public static function userRevocationKey(string $userId): string
    {
        return 'auth:jwt:revoked-before:' . $userId;
    }

    public function check(Request $request): SecurityVerdict
    {
        $header = $request->header('Authorization') ?? '';
        $token  = str_starts_with($header, 'Bearer ') ? trim(substr($header, 7)) : '';

        // The header wins; the cookie is the fallback for a navigation that
        // cannot carry one.
        if ($token === '' && $this->cookie !== '') {
            $token = trim((string) ($request->cookie($this->cookie) ?? ''));
        }

        if ($token === '') {
            // Anonymous request — let downstream authorization decide.
            return SecurityVerdict::allow($request);
        }

        if ($this->keys === [] && $this->secret === '') {
            return $this->refuse($request, 'Invalid or missing authentication token.');
        }

        // Clock-skew tolerance for exp/iat/nbf. The JWT library only exposes
        // this as a process-global static, so it must be set for OUR decode and
        // restored immediately.
        //
        // Previously it was assigned and never restored, and only when non-zero.
        // Both halves were wrong under a resident worker (Swoole):
        //   - not restoring leaked this layer's tolerance into every later
        //     decode in the process, including other components' ;
        //   - skipping the assignment when leeway is 0 meant a layer that wants
        //     STRICT checking silently inherited a previous layer's tolerance,
        //     so an expired token could verify.
        // Assign unconditionally, restore in finally.
        $previousLeeway = JWT::$leeway;
        JWT::$leeway    = max(0, $this->leeway);

        try {
            // Pin to a SINGLE algorithm — never let the token's own `alg` header
            // pick the verifier (prevents alg-confusion / HS-vs-RS downgrade).
            // With a rotation set the `kid` picks the KEY, never the algorithm.
            $claims = (array) JWT::decode($token, $this->verificationKeys());
        } catch (\Throwable) {
            return $this->refuse($request, 'Authentication token is invalid or expired.');
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        // Issuer / audience binding — reject tokens minted for another service or
        // tenant boundary even if the signature is valid.
        if ($this->issuer !== null && ($claims['iss'] ?? null) !== $this->issuer) {
            return $this->refuse($request, 'Authentication token issuer is not trusted.');
        }
        if ($this->audience !== null && !$this->audienceMatches($claims['aud'] ?? null)) {
            return $this->refuse($request, 'Authentication token audience is not accepted.');
        }

        // Revocation deny-list — a logged-out / compromised token is rejected
        // even though its signature and expiry are still valid. Fail OPEN on a
        // cache outage (the token is otherwise cryptographically valid) rather
        // than locking every user out when the cache is unreachable.
        $jti = (string) ($claims['jti'] ?? '');
        if ($this->revocations !== null && $jti !== '') {
            try {
                if ($this->revocations->has(self::revocationKey($jti))) {
                    return $this->refuse($request, 'Authentication token has been revoked.');
                }
            } catch (\Throwable) {
                // Cache unavailable — proceed on the valid signature.
            }
        }

        // Authority cutoff — every token this user held before their role,
        // tenant, device or status last changed is dead, while a token minted
        // since (a fresh sign-in) still works. Same fail-OPEN policy as the
        // deny-list above: a cache outage must not sign out the field.
        $subject = (string) ($claims['sub'] ?? '');
        if ($this->revocations !== null && $subject !== '') {
            try {
                $cutoff = $this->revocations->get(self::userRevocationKey($subject));
            } catch (\Throwable) {
                $cutoff = null;   // Cache unavailable — proceed on the valid signature.
            }

            if (is_numeric($cutoff)) {
                // No `iat` means the token cannot be shown to POST-DATE the
                // cutoff, and an unprovable token is refused rather than given
                // the benefit of the doubt — the cutoff exists precisely because
                // this user's outstanding tokens are not to be honoured.
                // AuthService::issueJwt() always stamps `iat`.
                $issuedAt = $claims['iat'] ?? null;

                if (!is_numeric($issuedAt) || (int) $issuedAt < (int) $cutoff) {
                    return $this->refuse($request, 'Authentication token has been revoked.');
                }
            }
        }

        // Tenant context rides on the signed `tnt` claim (legacy `tenant`
        // accepted for BC). Empty = UNSCOPED: the request keeps the central
        // connection (login, tenant picker, public pages). A non-empty tenant is
        // routed to its isolated DB by plugins/Tenancy's TenantContextStage,
        // which re-checks membership so a revoked seat loses access before expiry.
        $tenant = (string) ($claims['tnt'] ?? $claims['tenant'] ?? '');

        $identity = new Identity(
            userId:      $subject,
            tenantId:    $tenant,
            roles:       array_values((array) ($claims['roles'] ?? [])),
            permissions: array_values((array) ($claims['permissions'] ?? [])),
            tokenType:   'jwt',
            // Display-identity claims minted by AuthService::issueJwt() (OIDC
            // names). `name` is first + last from the tenant user_profiles table,
            // present only on tenant-scoped tokens.
            username:    (string) ($claims['preferred_username'] ?? ''),
            email:       (string) ($claims['email'] ?? ''),
            fullName:    (string) ($claims['name'] ?? ''),
        );

        return SecurityVerdict::allow($request->withIdentity($identity));
    }

    /**
     * The key, or keyed set, to verify against.
     *
     * A single key when no rotation set is configured; otherwise the map
     * firebase/php-jwt indexes by the token's `kid` header — a token naming a
     * key that is not here fails to decode, which is the refusal we want.
     *
     * @return Key|array<string, Key>
     */
    private function verificationKeys(): Key|array
    {
        if ($this->keys === []) {
            return new Key($this->secret, $this->algo);
        }

        $keys = [];
        foreach ($this->keys as $kid => $material) {
            $keys[(string) $kid] = new Key($material, $this->algo);
        }

        return $keys;
    }

    /**
     * A bad token, answered per {@see $denyInvalid}: 401 here, or a guest
     * identity for an application that refuses in its own error shape further
     * down. NEVER throws — a security layer returns a verdict (GDA rule).
     */
    private function refuse(Request $request, string $reason): SecurityVerdict
    {
        return $this->denyInvalid
            ? SecurityVerdict::deny(401, $reason)
            : SecurityVerdict::allow($request);
    }

    /** `aud` may be a single string or a list; accept when our audience is present. */
    private function audienceMatches(mixed $aud): bool
    {
        if (is_string($aud)) {
            return hash_equals($this->audience ?? '', $aud);
        }
        if (is_array($aud)) {
            foreach ($aud as $candidate) {
                if (is_string($candidate) && hash_equals($this->audience ?? '', $candidate)) {
                    return true;
                }
            }
        }

        return false;
    }
}
