<?php

declare(strict_types=1);

use AlfaCode\LetMigrate\Contract\MigrationInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;

/**
 * Auth — `personal_access_tokens` on the CENTRAL database, for tokens minted on
 * a host that resolves no tenant.
 *
 * Same reason as 2026_10_11_000010_create_auth_sessions_table: the token
 * repository writes to the sign-in database, which is central on a tenant-less
 * host.
 *
 * ONE migration here for what the tenant template does in two
 * (2026_06_05_000001_create_personal_access_tokens_table +
 * 2026_06_27_000002_add_expiry_and_abilities_to_personal_access_tokens): a new
 * central table is created in its final shape. A central table that already
 * exists (a project that created it itself) only gains the two later columns
 * if it lacks them. MigrationParityTest checks the created shape against the
 * tenant template's two steps.
 */
return new class implements MigrationInterface {
    public function up(SchemaBuilderInterface $schema): void
    {
        if ($schema->hasTable('personal_access_tokens')) {
            $schema->table('personal_access_tokens', static function ($t) use ($schema) {
                if (!$schema->hasColumn('personal_access_tokens', 'expires_at')) {
                    $t->timestamp('expires_at')->nullable();
                }
                if (!$schema->hasColumn('personal_access_tokens', 'abilities')) {
                    $t->text('abilities')->nullable();
                }
            });

            return;
        }

        $schema->create('personal_access_tokens', static function ($t) {
            $t->string('id', 64)->primary();
            $t->string('user_id', 64);
            $t->string('name', 255);
            $t->string('token_hash', 64)->unique();
            $t->timestamp('last_used_at')->nullable();
            $t->timestamp('created_at')->nullable();
            $t->timestamp('expires_at')->nullable();
            $t->text('abilities')->nullable();

            $t->index(['user_id']);
        });
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $schema->dropIfExists('personal_access_tokens');
    }
};
