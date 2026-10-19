<?php

declare(strict_types=1);

namespace Plugins\Auth\Domain\ValueObjects;

/**
 * Recaller — the parsed "remember me" cookie value.
 *
 * A plain pipe-delimited `id|token` string. NEVER unserialize user-controlled
 * cookie input — the recaller is always this flat string, so PHP object
 * injection is impossible. Zero external dependencies (Domain layer rule).
 *
 * Two shapes:
 *
 *   d:<device session id>|<token>   PER-DEVICE. The token belongs to one row
 *                                   of `auth_sessions`, so each browser has its
 *                                   own and rotating one never touches another.
 *   <user id>|<token>               LEGACY. The token is `users.remember_token`,
 *                                   ONE per user, so remembering a second device
 *                                   killed the first one's cookie. Still read,
 *                                   once, and replaced by a per-device cookie.
 */
final readonly class Recaller
{
    private const string DEVICE_PREFIX = 'd:';

    /** @var list<string> segments from a single explode */
    private array $parts;

    public function __construct(private string $value)
    {
        $this->parts = explode('|', $value, 2);
    }

    /** Compose a LEGACY (per-user) cookie value from its two segments. */
    public static function make(string $userId, string $token): self
    {
        return new self($userId . '|' . $token);
    }

    /** Compose a per-device cookie value: `d:<device session id>|<token>`. */
    public static function forDevice(string $deviceSessionId, string $token): self
    {
        return new self(self::DEVICE_PREFIX . $deviceSessionId . '|' . $token);
    }

    /** The first segment as written: a user id, or `d:<device id>`. */
    public function id(): string
    {
        return $this->parts[0] ?? '';
    }

    public function token(): string
    {
        return $this->parts[1] ?? '';
    }

    /** True for the per-device shape. */
    public function isDevice(): bool
    {
        return str_starts_with($this->id(), self::DEVICE_PREFIX);
    }

    /** The device session id of a per-device recaller, '' otherwise. */
    public function deviceSessionId(): string
    {
        return $this->isDevice() ? substr($this->id(), \strlen(self::DEVICE_PREFIX)) : '';
    }

    /** Both segments present and non-blank, and the delimiter was actually there. */
    public function valid(): bool
    {
        return str_contains($this->value, '|')
            && count($this->parts) === 2
            && trim($this->parts[0]) !== ''
            && trim($this->parts[1]) !== ''
            && (!$this->isDevice() || trim($this->deviceSessionId()) !== '');
    }

    public function value(): string
    {
        return $this->value;
    }
}
