<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\HttpStatusAware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Application\Exceptions\AuthorizationException;
use Plugins\Auth\Application\Exceptions\MissingScopeException;

/**
 * The status an authorization denial actually emits.
 *
 * `asNotFound()` did nothing for as long as it existed: it set a private
 * `$status` that nothing read. `ErrorStage::statusFor()` resolves a
 * SecurityException from `getCode()` and had never heard of `status()`, so
 * every "hide that this exists" denial answered 403 — which confirms the
 * resource exists. The README documented the masking as working.
 *
 * These tests pin the contract the pipeline actually consumes, which is
 * `HttpStatusAware::httpStatus()`. Asserting on `status()` instead would pass
 * against the broken version, because `status()` was never the thing that was
 * wrong.
 */
#[CoversClass(AuthorizationException::class)]
final class AuthorizationStatusTest extends TestCase
{
    public function testThePipelineCanReadTheStatusAtAll(): void
    {
        self::assertInstanceOf(HttpStatusAware::class, new AuthorizationException());
    }

    public function testAnOrdinaryDenialIsStill403(): void
    {
        self::assertSame(403, (new AuthorizationException())->httpStatus());
    }

    public function testAsNotFoundActuallyMasksAs404(): void
    {
        self::assertSame(404, (new AuthorizationException())->asNotFound()->httpStatus());
    }

    public function testAnExplicitStatusIsHonoured(): void
    {
        self::assertSame(451, (new AuthorizationException())->withStatus(451)->httpStatus());
    }

    public function testClearingTheOverrideFallsBackTo403(): void
    {
        self::assertSame(403, (new AuthorizationException())->asNotFound()->withStatus(null)->httpStatus());
    }

    /** The subclass inherits the fix — it is the one most likely to mask. */
    public function testMissingScopeMasksToo(): void
    {
        $e = (new MissingScopeException('users:read'))->asNotFound();

        self::assertInstanceOf(HttpStatusAware::class, $e);
        self::assertSame(404, $e->httpStatus());
    }

    /**
     * The kernel ignores a declared status outside 4xx/5xx and falls through,
     * so an override must never be able to turn a denial into a 200.
     */
    public function testTheCodeStillCarriesTheSecurityException403(): void
    {
        self::assertSame(403, (new AuthorizationException())->getCode());
    }
}
