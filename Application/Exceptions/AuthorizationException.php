<?php

declare(strict_types=1);

namespace Plugins\Auth\Application\Exceptions;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\HttpStatusAware;
use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\SecurityException;

/**
 * Thrown when an authenticated caller is denied by a gate/policy check.
 *
 * GDA-native port of the old __DEV__ AuthorizationException. Maps to HTTP 403 by
 * default; `asNotFound()` masks the resource as 404 (avoids leaking existence).
 *
 * ─── WHY HttpStatusAware ────────────────────────────────────────────────────
 *
 * `asNotFound()` did nothing for as long as it has existed. It set a private
 * `$status`, and nothing read it: `ErrorStage::statusFor()` resolves a
 * SecurityException from `getCode()` — 401/403/429, else 403 — and has never
 * known about `status()` or `hasStatus()`. So every call meant to hide a
 * resource's existence answered 403, which confirms the resource exists. That
 * is the precise leak the method was written to prevent, and the README
 * documented the behaviour as working.
 *
 * `HttpStatusAware` is the kernel's sanctioned hook and is checked FIRST, ahead
 * of the SecurityException branch. Returning 403 when nothing was overridden
 * keeps the default byte-identical.
 */
class AuthorizationException extends SecurityException implements HttpStatusAware
{
    private ?int $status = null;

    public function __construct(
        string $message = 'This action is unauthorized.',
        int|string $appCode = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, layer: 'auth.authorization', context: ['app_code' => $appCode], code: 403, previous: $previous);
    }

    /** Override the HTTP status the pipeline should emit (e.g. 404 to mask). */
    public function withStatus(?int $status): static
    {
        $this->status = $status;

        return $this;
    }

    /** Deny as 404 so the resource's existence is not revealed. */
    public function asNotFound(): static
    {
        return $this->withStatus(404);
    }

    public function hasStatus(): bool
    {
        return $this->status !== null;
    }

    public function status(): ?int
    {
        return $this->status;
    }

    /**
     * The status the pipeline emits. 403 unless `withStatus()`/`asNotFound()`
     * overrode it — so the default is exactly what it was before.
     */
    public function httpStatus(): int
    {
        return $this->status ?? 403;
    }
}
