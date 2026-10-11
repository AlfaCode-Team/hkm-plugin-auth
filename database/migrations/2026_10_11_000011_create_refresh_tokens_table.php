<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Auth — `refresh_tokens` on the CENTRAL database, for refresh-token sessions
 * issued on a host that resolves no tenant.
 *
 * Same reason as 2026_10_11_000010_create_auth_sessions_table: the refresh
 * store writes to the sign-in database, which is central on a tenant-less
 * host. Same columns and indexes as the tenant-template twin
 * (database/tenant-template/2026_07_04_000002_create_refresh_tokens_table.php);
 * MigrationParityTest keeps the two identical.
 *
 * Skips when the table already exists.
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        if ($schema->hasTable('refresh_tokens')) {
            return;
        }

        $schema->create('refresh_tokens', static function ($t) {
            $t->id();
            $t->char('token_id', 31);
            $t->char('family_id', 31)->comment('rotation lineage for reuse detection');
            $t->char('user_id', 31)
                ->comment('Soft ref to central users.user_id (ULID) — no cross-DB FK');
            $t->char('token_hash', 64)->comment('SHA-256 of the refresh token — never store raw');
            $t->char('tenant_id', 31)->nullable()->comment('scope hint for the tnt claim; not re-verified');
            $t->string('device', 191)->nullable()->comment('UA / device label');
            $t->string('ip', 45)->nullable();
            $t->timestamp('expires_at');
            $t->timestamp('revoked_at')->nullable();
            $t->timestamp('last_used_at')->nullable();
            $t->timestamp('created_at')->default('CURRENT_TIMESTAMP');

            $t->unique(['token_id'], 'uniq_token_id');
            $t->unique(['token_hash'], 'uniq_token_hash');
            $t->index(['user_id', 'revoked_at'], 'idx_user_active');
            $t->index(['family_id'], 'idx_family');


            $t->engine('InnoDB');
            $t->charset('utf8mb4');
            $t->rowFormat('DYNAMIC');
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $schema->dropIfExists('refresh_tokens');
    }
};
