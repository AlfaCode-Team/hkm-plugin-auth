<?php

declare(strict_types=1);

namespace Plugins\Auth\API;

/**
 * A recovery code — the printed one-time code that gets an account back when
 * every other factor is gone.
 *
 * Published as a dependency-free PRIMITIVE, with no opinion about storage: an
 * application keeps its codes in whichever table or column it likes and uses
 * this for the three parts that are easy to get subtly wrong — the alphabet,
 * the normaliser, and the digest.
 *
 * THE ALPHABET OMITS I, O, 0 AND 1 ON PURPOSE. These are read off a screen and
 * typed in by somebody who has just lost access to their own account, quite
 * possibly on a phone keyboard. A code that cannot be transcribed reliably is a
 * code that does not work, and the cost of the smaller alphabet is negligible:
 * 32^10 is still ~2^50.
 *
 * ONLY DIGESTS ARE STORED. The plaintext is shown to its owner exactly once —
 * a recovery code read back out of a database is a password-equivalent sitting
 * in plaintext, and the whole point of the code is to survive the compromise of
 * everything else.
 *
 * THE NORMALISER IS DELIBERATELY FORGIVING about how the code is typed — spaced,
 * lower case, with or without the hyphen — and deliberately SILENT about why a
 * code is unacceptable. It returns '' for anything that could never be one of
 * ours, so a caller reports "invalid" identically for malformed, unknown and
 * already-used. Reporting "malformed" separately tells somebody holding a guess
 * whether they have the right shape.
 */
final readonly class RecoveryCode
{
    /** Crockford-ish: no I, O, 0 or 1 — see the class docblock. */
    public const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    /** A conventional set size; `mintSet()` takes any count. */
    public const COUNT = 8;

    /** Characters per group; a code is two groups joined by a hyphen. */
    private const GROUP = 5;

    private function __construct(public string $value)
    {
    }

    /** One code, `XXXXX-XXXXX`. */
    public static function mint(): self
    {
        $max = strlen(self::ALPHABET) - 1;
        $out = '';

        for ($i = 0; $i < self::GROUP * 2; $i++) {
            // random_int, never rand()/mt_rand(): this is a credential.
            $out .= self::ALPHABET[random_int(0, $max)];
        }

        return new self(substr($out, 0, self::GROUP) . '-' . substr($out, self::GROUP));
    }

    /** @return list<self> */
    public static function mintSet(int $count = self::COUNT): array
    {
        $codes = [];
        for ($i = 0; $i < max(1, $count); $i++) {
            $codes[] = self::mint();
        }

        return $codes;
    }

    /**
     * Canonicalise whatever was typed into `XXXXX-XXXXX`, or '' when it could
     * never be one of ours.
     */
    public static function normalise(?string $raw): string
    {
        $bare = strtoupper((string) preg_replace('/[^A-Za-z0-9]+/', '', (string) $raw));

        if (strlen($bare) !== self::GROUP * 2 || strspn($bare, self::ALPHABET) !== strlen($bare)) {
            return '';
        }

        return substr($bare, 0, self::GROUP) . '-' . substr($bare, self::GROUP);
    }

    /**
     * Digest for storage. The pepper is application-wide and lives OUTSIDE the
     * database, so a stolen table alone does not let an attacker test guesses
     * offline against it.
     */
    public static function digest(string $normalised, string $pepper): string
    {
        return hash_hmac('sha256', $normalised, $pepper);
    }

    public function digestWith(string $pepper): string
    {
        return self::digest($this->value, $pepper);
    }

    /**
     * Constant-time check of a submitted code against ONE stored digest.
     *
     * For codes kept as a SET on the account (a JSON column, a row per code)
     * — compare against each without stopping at the first hit, so the time
     * taken does not reveal the position of the match. An application that
     * instead LOOKS THE DIGEST UP (`WHERE digest = ?`) needs none of this:
     * hash the normalised code with {@see digest()} and query for it.
     */
    public static function matches(?string $submitted, string $storedDigest, string $pepper): bool
    {
        $normalised = self::normalise($submitted);
        $usable     = $normalised !== '';

        // Digest and compare EVEN when the input was malformed, so a wrong
        // shape and a wrong code cost the same. The validity is folded in
        // afterwards rather than returned early.
        $candidate = self::digest($usable ? $normalised : str_repeat('A', self::GROUP * 2 + 1), $pepper);
        $equal     = hash_equals($storedDigest, $candidate);

        return $usable && $equal;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
