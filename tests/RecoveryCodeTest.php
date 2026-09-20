<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\API\RecoveryCode;

/**
 * The properties that make a recovery code usable by somebody locked out, and
 * safe against somebody guessing.
 */
#[CoversClass(RecoveryCode::class)]
final class RecoveryCodeTest extends TestCase
{
    public function test_a_minted_code_is_transcribable(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $code = (string) RecoveryCode::mint();

            self::assertMatchesRegularExpression('/^[A-Z2-9]{5}-[A-Z2-9]{5}$/', $code);

            // Read off a screen and typed on a phone: these four are the pairs
            // people transpose, so they are not in the alphabet at all.
            foreach (['I', 'O', '0', '1'] as $ambiguous) {
                self::assertStringNotContainsString($ambiguous, $code, "[{$ambiguous}] is ambiguous in print");
            }
        }
    }

    public function test_mint_set_returns_distinct_codes(): void
    {
        $codes = array_map('strval', RecoveryCode::mintSet());

        self::assertCount(RecoveryCode::COUNT, $codes);
        self::assertSame($codes, array_unique($codes), 'a duplicate code is one fewer recovery than the user was promised');

        self::assertCount(3, RecoveryCode::mintSet(3));
        self::assertCount(1, RecoveryCode::mintSet(0), 'a set is never empty');
    }

    /** @return iterable<string, array{string}> */
    public static function typedForms(): iterable
    {
        yield 'as printed'    => ['ABCDE-FGHJK'];
        yield 'lower case'    => ['abcde-fghjk'];
        yield 'no hyphen'     => ['ABCDEFGHJK'];
        yield 'spaced'        => ['ABCDE FGHJK'];
        yield 'spaced twice'  => [' ABC DE-FG HJK '];
        yield 'underscored'   => ['ABCDE_FGHJK'];
    }

    #[DataProvider('typedForms')]
    public function test_the_normaliser_accepts_the_code_however_it_is_typed(string $typed): void
    {
        self::assertSame('ABCDE-FGHJK', RecoveryCode::normalise($typed));
    }

    /** @return iterable<string, array{?string}> */
    public static function unusable(): iterable
    {
        yield 'null'            => [null];
        yield 'empty'           => [''];
        yield 'too short'       => ['ABCDE-FGHJ'];
        yield 'too long'        => ['ABCDE-FGHJKL'];
        yield 'ambiguous chars' => ['ABCDE-FGHI0'];
        yield 'punctuation only'=> ['-----'];
    }

    #[DataProvider('unusable')]
    public function test_anything_that_could_never_be_ours_normalises_to_empty(?string $raw): void
    {
        self::assertSame('', RecoveryCode::normalise($raw));
    }

    public function test_the_digest_is_peppered_so_a_stolen_table_cannot_be_tested_offline(): void
    {
        $code = 'ABCDE-FGHJK';

        $a = RecoveryCode::digest($code, 'pepper-one');
        $b = RecoveryCode::digest($code, 'pepper-two');

        self::assertNotSame($a, $b, 'the pepper must change the digest');
        self::assertSame($a, RecoveryCode::digest($code, 'pepper-one'), 'and be deterministic');
        self::assertStringNotContainsStringIgnoringCase($code, $a, 'the plaintext must not survive into storage');
    }

    public function test_digest_with_matches_the_static_digest(): void
    {
        $code = RecoveryCode::mint();

        self::assertSame(
            RecoveryCode::digest((string) $code, 'pepper'),
            $code->digestWith('pepper'),
        );
    }

    public function test_matches_accepts_the_right_code_in_any_form_and_refuses_the_rest(): void
    {
        $code   = RecoveryCode::mint();
        $stored = $code->digestWith('pepper');

        self::assertTrue(RecoveryCode::matches((string) $code, $stored, 'pepper'));
        self::assertTrue(RecoveryCode::matches(strtolower(str_replace('-', ' ', (string) $code)), $stored, 'pepper'));

        self::assertFalse(RecoveryCode::matches((string) RecoveryCode::mint(), $stored, 'pepper'), 'another code');
        self::assertFalse(RecoveryCode::matches((string) $code, $stored, 'other-pepper'), 'another pepper');
        self::assertFalse(RecoveryCode::matches('not-a-code', $stored, 'pepper'), 'malformed');
        self::assertFalse(RecoveryCode::matches(null, $stored, 'pepper'), 'nothing at all');
    }
}
