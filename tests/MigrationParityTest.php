<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfaCode\LetMigrate\Contract\DatabaseDriverInterface;
use AlfaCode\LetMigrate\Contract\SchemaBuilderInterface;
use AlfaCode\LetMigrate\Driver\MySQL\MySQLGrammar;
use AlfaCode\LetMigrate\Schema\Blueprint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Each auth table exists twice: in the tenant template (tenant sign-ins) and in
 * the central migrations (sign-ins on a host that resolves no tenant). The same
 * repositories read both, so the two must create the same table, column for
 * column and index for index.
 *
 * Compared through the real MySQL grammar, with no database: each migration is
 * run against a recording SchemaBuilder and the resulting CREATE TABLE
 * statements must be identical. The tenant `personal_access_tokens` is built in
 * two steps (create, then add expiry + abilities); both are replayed onto one
 * table before comparing, since the central migration creates the final shape
 * in one.
 */
final class MigrationParityTest extends TestCase
{
    private const string ROOT = __DIR__ . '/../database';

    /** @return iterable<string, array{0: string, 1: list<string>, 2: list<string>}> table, central files, tenant files */
    public static function tables(): iterable
    {
        yield 'auth_sessions' => [
            'auth_sessions',
            [
                'migrations/2026_10_11_000010_create_auth_sessions_table.php',
                'migrations/2026_10_19_000001_add_remember_hash_to_auth_sessions_table.php',
            ],
            [
                'tenant-template/2026_07_12_000001_create_auth_sessions_table.php',
                'tenant-template/2026_10_19_000001_add_remember_hash_to_auth_sessions_table.php',
            ],
        ];
        yield 'refresh_tokens' => [
            'refresh_tokens',
            ['migrations/2026_10_11_000011_create_refresh_tokens_table.php'],
            ['tenant-template/2026_07_04_000002_create_refresh_tokens_table.php'],
        ];
        yield 'personal_access_tokens' => [
            'personal_access_tokens',
            ['migrations/2026_10_11_000012_create_personal_access_tokens_table.php'],
            [
                'tenant-template/2026_06_05_000001_create_personal_access_tokens_table.php',
                'tenant-template/2026_06_27_000002_add_expiry_and_abilities_to_personal_access_tokens.php',
            ],
        ];
    }

    /**
     * @param list<string> $central
     * @param list<string> $tenant
     */
    #[DataProvider('tables')]
    public function test_central_and_tenant_create_the_same_table(string $table, array $central, array $tenant): void
    {
        $centralSql = self::compile($table, $central);
        $tenantSql = self::compile($table, $tenant);

        self::assertStringContainsString("CREATE TABLE `{$table}`", $centralSql);
        self::assertSame($tenantSql, $centralSql);
    }

    public function test_every_central_migration_skips_a_table_that_already_exists(): void
    {
        foreach (['auth_sessions' => '000010_create_auth_sessions', 'refresh_tokens' => '000011_create_refresh_tokens'] as $table => $file) {
            $schema = new RecordingSchema([$table]);
            (require self::ROOT . "/migrations/2026_10_11_{$file}_table.php")->up($schema);
            self::assertSame([], $schema->created, $table);
        }

        // An existing personal_access_tokens only gains the columns it lacks.
        $schema = new RecordingSchema(['personal_access_tokens']);
        (require self::ROOT . '/migrations/2026_10_11_000012_create_personal_access_tokens_table.php')->up($schema);
        self::assertSame([], $schema->created);
        self::assertSame(['expires_at', 'abilities'], array_map(
            static fn ($c): string => $c->getName(),
            $schema->tables['personal_access_tokens']->getColumns(),
        ));
    }

    /** @param list<string> $files */
    private static function compile(string $table, array $files): string
    {
        $schema = new RecordingSchema();
        foreach ($files as $file) {
            (require self::ROOT . '/' . $file)->up($schema);
        }

        self::assertArrayHasKey($table, $schema->tables, "{$table} was not created by " . implode(', ', $files));

        return (new MySQLGrammar())->compileCreate($schema->tables[$table]);
    }
}

/**
 * A SchemaBuilder that only records: create() builds a Blueprint, table() keeps
 * adding to the same one, so a create followed by an alter yields the final
 * table. Nothing reaches a database.
 */
final class RecordingSchema implements SchemaBuilderInterface
{
    /** @var array<string, Blueprint> */
    public array $tables = [];

    /** @var list<string> */
    public array $created = [];

    /** @param list<string> $existing tables to report as already present */
    public function __construct(private array $existing = [])
    {
    }

    public function create(string $table, callable $callback): void
    {
        $blueprint = new Blueprint($table);
        $callback($blueprint);
        $this->tables[$table] = $blueprint;
        $this->created[] = $table;
    }

    public function table(string $table, callable $callback): void
    {
        $this->tables[$table] ??= new Blueprint($table);
        $callback($this->tables[$table]);
    }

    public function drop(string $table): void
    {
        unset($this->tables[$table]);
    }

    public function dropIfExists(string $table): void
    {
        unset($this->tables[$table]);
    }

    public function rename(string $from, string $to): void
    {
        throw new \LogicException('not used by these migrations');
    }

    public function hasTable(string $table): bool
    {
        return isset($this->tables[$table]) || in_array($table, $this->existing, true);
    }

    public function hasColumn(string $table, string $column): bool
    {
        // Answered from the recorded Blueprint; a table reported as existing
        // through $existing has no recorded columns, so it lacks them all.
        foreach (($this->tables[$table] ?? null)?->getColumns() ?? [] as $definition) {
            if ($definition->getName() === $column) {
                return true;
            }
        }

        return false;
    }

    public function raw(string $sql, array $bindings = []): void
    {
        throw new \LogicException('not used by these migrations');
    }

    public function disableForeignKeyChecks(): void
    {
    }

    public function enableForeignKeyChecks(): void
    {
    }

    public function getDriver(): DatabaseDriverInterface
    {
        throw new \LogicException('not used by these migrations');
    }
}
