<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Infrastructure\Http\Controllers\SessionStartController;

/**
 * The open-redirect rule every `next` / `redirectTo` / session target goes
 * through. Browsers strip tab and newline from a URL before parsing it, so a
 * prefix check alone lets `/<TAB>//evil.test` leave the site.
 */
#[CoversClass(SessionStartController::class)]
final class SafeRedirectTargetTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function offsite(): iterable
    {
        yield 'absolute URL'          => ['https://evil.test/'];
        yield 'protocol-relative'     => ['//evil.test'];
        yield 'backslash after slash' => ['/\\evil.test'];
        yield 'backslash later'       => ['/a\\..\\\\evil.test'];
        yield 'tab then //'           => ["/\t//evil.test"];
        yield 'newline then //'       => ["/\n//evil.test"];
        yield 'carriage return'       => ["/\r//evil.test"];
        yield 'NUL'                   => ["/\0//evil.test"];
        yield 'space then //'         => ['/ //evil.test'];
        yield 'DEL'                   => ["/\x7F//evil.test"];
        yield 'not a path'            => ['evil.test'];
        yield 'empty'                 => [''];
    }

    #[DataProvider('offsite')]
    public function testRefusesAnythingThatCanLeaveTheSite(string $target): void
    {
        self::assertNull(SessionStartController::safeTarget($target));
    }

    public function testKeepsAnOrdinaryPathWithItsQuery(): void
    {
        self::assertSame('/campaigns/nile?tab=vote&x=%2F%2F', SessionStartController::safeTarget('/campaigns/nile?tab=vote&x=%2F%2F'));
        self::assertSame('/', SessionStartController::safeTarget('/'));
    }

    public function testRefusesNonStrings(): void
    {
        self::assertNull(SessionStartController::safeTarget(null));
        self::assertNull(SessionStartController::safeTarget(['/x']));
    }
}
