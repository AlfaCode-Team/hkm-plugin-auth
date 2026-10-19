<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Auth — per-device "remember me": `auth_sessions.remember_hash` (CENTRAL).
 *
 * The remember-me token used to be `users.remember_token`, ONE per user, so
 * remembering a second device rotated it and the first device's cookie stopped
 * working. It now lives on the device's own `auth_sessions` row: SHA-256 of
 * that device's token, NULL when the sign-in was not remembered. Rotating it
 * on use touches only that row, and revoking the row (sign out, "sign out
 * other devices", a password reset) ends that device's remember-me with it.
 *
 * Looked up through the existing unique `session_id` (the cookie carries it),
 * so no new index. Twin of the tenant-template migration of the same name;
 * MigrationParityTest keeps the two identical.
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        if (!$schema->hasTable('auth_sessions')) {
            return;
        }

        $schema->table('auth_sessions', static function ($t) use ($schema) {
            if (!$schema->hasColumn('auth_sessions', 'remember_hash')) {
                $t->char('remember_hash', 64)->nullable()
                    ->comment("SHA-256 of this device's remember-me token; NULL = not remembered");
            }
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        if (!$schema->hasTable('auth_sessions')) {
            return;
        }

        $schema->table('auth_sessions', static function ($t) use ($schema) {
            if ($schema->hasColumn('auth_sessions', 'remember_hash')) {
                $t->dropColumn('remember_hash');
            }
        });
    }
};
