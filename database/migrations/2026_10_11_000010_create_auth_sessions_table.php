<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Auth — `auth_sessions` on the CENTRAL database, for sign-ins on a host that
 * resolves no tenant.
 *
 * Every auth repository writes to the SIGN-IN database: the per-request
 * `DatabasePort` (Provider::signInDb()). On a tenant host that is the tenant's
 * database, which gets this table from database/tenant-template/. On a host
 * that resolves NO tenant — a platform console, a marketing apex, anything in
 * TENANCY_CENTRAL_DOMAINS, or a project with no Tenancy plugin at all — it is
 * the central database, which until now never had the table, so every session
 * sign-in there failed with "Table '<central>.auth_sessions' doesn't exist".
 *
 * Same columns and indexes as the tenant-template twin
 * (database/tenant-template/2026_07_12_000001_create_auth_sessions_table.php);
 * MigrationParityTest keeps the two identical. Tenant sign-ins are unchanged:
 * they still land in their tenant database, never here.
 *
 * Skips when the table already exists (a project that created it itself).
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        if ($schema->hasTable('auth_sessions')) {
            return;
        }

        $schema->create('auth_sessions', static function ($t) {
            $t->id();
            $t->char('session_id', 32)->comment('public id (list/revoke API) — not the token');
            $t->char('user_id', 31)
                ->comment('Soft ref to central users.user_id (ULID) — no cross-DB FK');
            $t->char('token_hash', 64)->comment('SHA-256 of the session token — never store raw');
            $t->char('fingerprint', 64)->nullable()->comment('SHA-256 device fingerprint captured at login');
            $t->string('ip', 45)->nullable();
            $t->string('user_agent', 191)->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->timestamp('expires_at');
            $t->timestamp('revoked_at')->nullable();
            $t->timestamp('created_at')->default('CURRENT_TIMESTAMP');

            $t->unique(['session_id'], 'uniq_session_id');
            $t->unique(['token_hash'], 'uniq_token_hash');
            $t->index(['user_id', 'revoked_at'], 'idx_user_active');


            $t->engine('InnoDB');
            $t->charset('utf8mb4');
            $t->rowFormat('DYNAMIC');
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $schema->dropIfExists('auth_sessions');
    }
};
