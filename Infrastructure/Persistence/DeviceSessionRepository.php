<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Persistence;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\RepositoryException;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;

/**
 * Persists server-side device sessions (hashed tokens) via DatabasePort only.
 *
 * Table: auth_sessions(session_id, user_id, token_hash, remember_hash,
 *        fingerprint, ip, user_agent, last_seen_at, expires_at, revoked_at,
 *        created_at)
 *
 * `remember_hash` (per-device remember-me) arrived in a later migration. A
 * database that has not run it yet must keep signing people in, so every
 * statement naming the column falls back to the old shape the first time the
 * column turns out to be missing, and remember-me then uses the legacy
 * per-user token ({@see self::remembersPerDevice()}). Reads use `SELECT *` so
 * they work on either shape.
 */
final class DeviceSessionRepository
{
    /** null = not known yet; false once a statement found the column missing. */
    private ?bool $rememberColumn = null;

    public function __construct(
        private readonly DatabasePort $db,
        private readonly string $table = 'auth_sessions',
    ) {
    }

    /** False once this database turned out to lack `remember_hash` (migration not run). */
    public function remembersPerDevice(): bool
    {
        return $this->rememberColumn !== false;
    }

    /**
     * Open a row. Returns true when `$rememberHash` was stored, false when it
     * was not asked for or this database cannot store it yet.
     */
    public function insert(
        string $sessionId,
        string $userId,
        string $tokenHash,
        ?string $fingerprint,
        ?string $ip,
        ?string $userAgent,
        \DateTimeImmutable $expiresAt,
        ?string $rememberHash = null,
    ): bool {
        $params = [
            'session_id'   => $sessionId,
            'user_id'      => $userId,
            'token_hash'   => $tokenHash,
            'fingerprint'  => $fingerprint,
            'ip'           => $ip !== null ? mb_substr($ip, 0, 45) : null,
            'user_agent'   => $userAgent !== null ? mb_substr($userAgent, 0, 191) : null,
            'last_seen_at' => self::now(),
            'expires_at'   => $expiresAt->format('Y-m-d H:i:s'),
            'created_at'   => self::now(),
        ];
        $columns = 'session_id, user_id, token_hash, fingerprint, ip, user_agent, last_seen_at, expires_at, created_at';
        $values  = ':session_id, :user_id, :token_hash, :fingerprint, :ip, :user_agent, :last_seen_at, :expires_at, :created_at';

        if ($rememberHash !== null && $this->remembersPerDevice()) {
            try {
                $this->db->execute(
                    "INSERT INTO {$this->table} ({$columns}, remember_hash) VALUES ({$values}, :remember_hash)",
                    $params + ['remember_hash' => $rememberHash],
                );

                return $this->rememberColumn = true;
            } catch (\RuntimeException $e) {
                if (!$this->markIfColumnMissing($e)) {
                    throw new RepositoryException('Failed to open device session', layer: 'repository.auth', previous: $e);
                }
                // Not migrated yet: open the row without it, remember-me goes legacy.
            }
        }

        try {
            $this->db->execute("INSERT INTO {$this->table} ({$columns}) VALUES ({$values})", $params);
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to open device session', layer: 'repository.auth', previous: $e);
        }

        return false;
    }

    /**
     * Look up an UNREVOKED session by its token hash. Expiry is enforced in PHP
     * by the caller (driver-portable — no NOW() dialect branching).
     *
     * @return array<string,mixed>|null includes `remember_hash` once migrated
     */
    public function findActiveByHash(string $tokenHash): ?array
    {
        try {
            return $this->db->queryOne(
                "SELECT * FROM {$this->table} WHERE token_hash = :hash AND revoked_at IS NULL",
                ['hash' => $tokenHash]
            );
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to look up device session', layer: 'repository.auth', previous: $e);
        }
    }

    /**
     * Look up an UNREVOKED session by its public id — how a per-device
     * remember-me cookie finds its row (unique index, no extra one needed).
     *
     * @return array<string,mixed>|null
     */
    public function findActiveBySessionId(string $sessionId): ?array
    {
        try {
            return $this->db->queryOne(
                "SELECT * FROM {$this->table} WHERE session_id = :id AND revoked_at IS NULL",
                ['id' => $sessionId]
            );
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to look up device session', layer: 'repository.auth', previous: $e);
        }
    }

    /**
     * Swap a remembered device's secrets after its remember-me cookie was used:
     * new session token, new remember token, the device's current fingerprint,
     * IP and agent, a fresh expiry.
     *
     * Compare-and-swap on the OLD remember hash, so one cookie value resumes
     * the device exactly once: a second request racing with the same cookie
     * changes nothing and gets false.
     */
    public function resume(
        string $sessionId,
        string $oldRememberHash,
        string $tokenHash,
        string $rememberHash,
        ?string $fingerprint,
        ?string $ip,
        ?string $userAgent,
        \DateTimeImmutable $expiresAt,
    ): bool {
        try {
            return $this->db->execute(
                "UPDATE {$this->table}
                    SET token_hash = :token_hash, remember_hash = :remember_hash, fingerprint = :fingerprint,
                        ip = :ip, user_agent = :user_agent, last_seen_at = :now, expires_at = :expires_at
                  WHERE session_id = :id AND revoked_at IS NULL AND remember_hash = :old",
                [
                    'token_hash'    => $tokenHash,
                    'remember_hash' => $rememberHash,
                    'fingerprint'   => $fingerprint,
                    'ip'            => $ip !== null ? mb_substr($ip, 0, 45) : null,
                    'user_agent'    => $userAgent !== null ? mb_substr($userAgent, 0, 191) : null,
                    'now'           => self::now(),
                    'expires_at'    => $expiresAt->format('Y-m-d H:i:s'),
                    'id'            => $sessionId,
                    'old'           => $oldRememberHash,
                ]
            ) > 0;
        } catch (\RuntimeException $e) {
            if ($this->markIfColumnMissing($e)) {
                return false;
            }
            throw new RepositoryException('Failed to resume device session', layer: 'repository.auth', previous: $e);
        }
    }

    /** Give a live row a new remember hash (or clear it with null). True when a row changed. */
    public function setRememberHash(string $sessionId, ?string $rememberHash, \DateTimeImmutable $expiresAt): bool
    {
        if (!$this->remembersPerDevice()) {
            return false;
        }

        try {
            return $this->db->execute(
                "UPDATE {$this->table} SET remember_hash = :remember_hash, expires_at = :expires_at
                  WHERE session_id = :id AND revoked_at IS NULL",
                ['remember_hash' => $rememberHash, 'expires_at' => $expiresAt->format('Y-m-d H:i:s'), 'id' => $sessionId]
            ) > 0;
        } catch (\RuntimeException $e) {
            if ($this->markIfColumnMissing($e)) {
                return false;
            }
            throw new RepositoryException('Failed to update device session', layer: 'repository.auth', previous: $e);
        }
    }

    /**
     * Stamp last-seen and (for rolling refresh) push the expiry forward.
     * Best-effort — observability + sliding lifetime, not an auth gate.
     */
    public function touch(string $sessionId, ?\DateTimeImmutable $newExpiresAt = null): void
    {
        $params = [
            'now' => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            'id'  => $sessionId,
        ];
        $set = 'last_seen_at = :now';

        if ($newExpiresAt !== null) {
            $set .= ', expires_at = :expires_at';
            $params['expires_at'] = $newExpiresAt->format('Y-m-d H:i:s');
        }

        try {
            $this->db->execute("UPDATE {$this->table} SET {$set} WHERE session_id = :id", $params);
        } catch (\RuntimeException) {
            // Non-fatal.
        }
    }

    public function revokeByHash(string $tokenHash): void
    {
        try {
            $this->db->execute(
                "UPDATE {$this->table} SET revoked_at = :now WHERE token_hash = :hash AND revoked_at IS NULL",
                ['now' => (new \DateTimeImmutable())->format('Y-m-d H:i:s'), 'hash' => $tokenHash]
            );
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to revoke device session', layer: 'repository.auth', previous: $e);
        }
    }

    /** Revoke one of a user's sessions by its public id. True when a row changed. */
    public function revokeForUser(string $userId, string $sessionId): bool
    {
        try {
            return $this->db->execute(
                "UPDATE {$this->table} SET revoked_at = :now
                 WHERE user_id = :user_id AND session_id = :id AND revoked_at IS NULL",
                [
                    'now'     => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
                    'user_id' => $userId,
                    'id'      => $sessionId,
                ]
            ) > 0;
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to revoke device session', layer: 'repository.auth', previous: $e);
        }
    }

    /** Revoke every active session for a user, optionally sparing one (the current device). */
    public function revokeAllForUser(string $userId, ?string $exceptSessionId = null): int
    {
        $sql    = "UPDATE {$this->table} SET revoked_at = :now WHERE user_id = :user_id AND revoked_at IS NULL";
        $params = [
            'now'     => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            'user_id' => $userId,
        ];

        if ($exceptSessionId !== null) {
            $sql .= ' AND session_id <> :except';
            $params['except'] = $exceptSessionId;
        }

        try {
            return $this->db->execute($sql, $params);
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to revoke device sessions', layer: 'repository.auth', previous: $e);
        }
    }

    /**
     * All active (unrevoked, unexpired) sessions for a user, newest first.
     * Never returns a token or remember hash; `remembered` says whether the
     * device had "keep me signed in".
     *
     * @return list<array{session_id:string,ip:?string,user_agent:?string,last_seen_at:?string,created_at:?string,expires_at:string,remembered:bool}>
     */
    public function listActiveForUser(string $userId): array
    {
        try {
            $rows = $this->db->query(
                "SELECT * FROM {$this->table}
                 WHERE user_id = :user_id AND revoked_at IS NULL AND expires_at > :cutoff
                 ORDER BY created_at DESC",
                [
                    'user_id' => $userId,
                    'cutoff'  => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
                ]
            );
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to list device sessions', layer: 'repository.auth', previous: $e);
        }

        return array_values(array_map(static fn (array $row): array => [
            'session_id'   => (string) $row['session_id'],
            'ip'           => $row['ip'] ?? null,
            'user_agent'   => $row['user_agent'] ?? null,
            'last_seen_at' => $row['last_seen_at'] ?? null,
            'created_at'   => $row['created_at'] ?? null,
            'expires_at'   => (string) $row['expires_at'],
            'remembered'   => ($row['remember_hash'] ?? null) !== null,
        ], $rows));
    }

    /** Delete expired/revoked rows older than the cutoff (maintenance). */
    public function deleteStale(?\DateTimeImmutable $now = null): int
    {
        $cutoff = ($now ?? new \DateTimeImmutable())->format('Y-m-d H:i:s');

        try {
            return $this->db->execute(
                "DELETE FROM {$this->table} WHERE expires_at <= :cutoff OR revoked_at IS NOT NULL",
                ['cutoff' => $cutoff]
            );
        } catch (\RuntimeException $e) {
            throw new RepositoryException('Failed to prune device sessions', layer: 'repository.auth', previous: $e);
        }
    }

    /**
     * Is this failure "the remember_hash column does not exist"? Then remember
     * that, so later statements skip it. MySQL says "Unknown column", SQLite
     * "no such column" / "has no column named"; all of them name the column.
     */
    private function markIfColumnMissing(\Throwable $e): bool
    {
        for ($t = $e; $t !== null; $t = $t->getPrevious()) {
            if (str_contains($t->getMessage(), 'remember_hash')) {
                $this->rememberColumn = false;

                return true;
            }
        }

        return false;
    }

    private static function now(): string
    {
        return (new \DateTimeImmutable())->format('Y-m-d H:i:s');
    }
}
