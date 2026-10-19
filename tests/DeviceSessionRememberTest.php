<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\DatabasePort;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Application\Services\DeviceSessionService;
use Plugins\Auth\Domain\ValueObjects\Recaller;
use Plugins\Auth\Infrastructure\Persistence\DeviceSessionRepository;
use Plugins\Database\Infrastructure\Drivers\SQLiteConfiguration;
use Plugins\Database\Infrastructure\Persistence\MultiDriverDatabaseAdapter;
use Tests\Unit\Plugins\Auth\Support\FakeSession;

/**
 * Per-device remember-me and device-row lifetimes, against REAL SQL: the
 * repository runs on an in-memory SQLite database through the Database
 * plugin's adapter, with `auth_sessions` in its migrated shape — or, for the
 * fallback, the shape it had before the `remember_hash` migration.
 *
 * Not covered here: MySQL/MariaDB (the SQL is plain and portable, and the
 * column-missing fallback matches on the column name, which every driver's
 * message carries), and the cookie round trip (SessionAuthStageDeviceRememberTest).
 */
#[CoversClass(DeviceSessionService::class)]
#[CoversClass(DeviceSessionRepository::class)]
#[CoversClass(Recaller::class)]
final class DeviceSessionRememberTest extends TestCase
{
    private const string USER = 'user-1';
    private const int SESSION_TTL = 7200;

    private DatabasePort $db;
    private DeviceSessionService $devices;

    protected function setUp(): void
    {
        $this->useDatabase(migrated: true);
    }

    private function useDatabase(bool $migrated): void
    {
        $this->db = new MultiDriverDatabaseAdapter(new SQLiteConfiguration(':memory:'));
        $this->db->execute('CREATE TABLE auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id CHAR(32) NOT NULL UNIQUE,
            user_id CHAR(31) NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE,
            fingerprint CHAR(64) NULL,
            ip VARCHAR(45) NULL,
            user_agent VARCHAR(191) NULL,
            last_seen_at TIMESTAMP NULL,
            expires_at TIMESTAMP NOT NULL,
            revoked_at TIMESTAMP NULL,
            created_at TIMESTAMP NULL'
            . ($migrated ? ', remember_hash CHAR(64) NULL' : '') . ')');

        $this->devices = new DeviceSessionService(
            new DeviceSessionRepository($this->db),
            sessionTtlSeconds: self::SESSION_TTL,
        );
    }

    private static function device(string $ip, string $agent = 'Phone'): Request
    {
        return Request::build('GET', '/', headers: ['User-Agent' => $agent], server: ['REMOTE_ADDR' => $ip]);
    }

    /** @return list<array<string,mixed>> */
    private function rows(): array
    {
        return $this->db->query('SELECT * FROM auth_sessions ORDER BY id');
    }

    private function secondsUntil(string $when): int
    {
        return (new \DateTimeImmutable($when))->getTimestamp() - time();
    }

    // ── Per-device remember-me ──────────────────────────────────────────────

    public function test_two_remembered_devices_each_keep_their_own_cookie(): void
    {
        $phone  = $this->devices->establish(new FakeSession(), self::device('10.0.0.1'), self::USER, remember: true);
        $laptop = $this->devices->establish(new FakeSession(), self::device('10.0.0.2', 'Laptop'), self::USER, remember: true);

        self::assertNotNull($phone);
        self::assertNotNull($laptop);
        self::assertTrue($phone->isDevice());

        // Remembering the laptop did not touch the phone: both still resume.
        self::assertNotNull($this->devices->resume(new FakeSession(), self::device('10.0.0.9'), $phone));
        self::assertNotNull($this->devices->resume(new FakeSession(), self::device('10.0.0.2', 'Laptop'), $laptop));
    }

    public function test_coming_back_resumes_the_same_row_instead_of_opening_a_new_one(): void
    {
        $cookie = $this->devices->establish(new FakeSession(), self::device('10.0.0.1'), self::USER, remember: true);

        for ($i = 0; $i < 5; $i++) {
            $session = new FakeSession();
            $resumed = $this->devices->resume($session, self::device('10.0.1.' . $i), $cookie);
            self::assertNotNull($resumed, "visit $i");
            self::assertSame(self::USER, $resumed['userId']);
            self::assertNotSame('', $session->get(DeviceSessionService::SESSION_DEVICE_TOKEN, ''));
            $cookie = $resumed['recaller'];
        }

        $rows = $this->rows();
        self::assertCount(1, $rows, 'one browser, one row');
        self::assertSame('10.0.1.4', $rows[0]['ip'], 're-bound to where the device is now');
    }

    public function test_a_used_cookie_cannot_be_used_again(): void
    {
        $cookie = $this->devices->establish(new FakeSession(), self::device('10.0.0.1'), self::USER, remember: true);

        self::assertNotNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), $cookie));
        // The same value again (a stolen copy, or a second tab racing): refused.
        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), $cookie));
    }

    public function test_a_resumed_session_verifies_and_the_old_session_token_does_not(): void
    {
        $old = new FakeSession();
        $cookie = $this->devices->establish($old, self::device('10.0.0.1'), self::USER, remember: true);

        $new = new FakeSession();
        $this->devices->resume($new, self::device('10.0.0.5'), $cookie);

        self::assertTrue($this->devices->verify($new, self::device('10.0.0.5')));
        self::assertFalse($this->devices->verify($old, self::device('10.0.0.1')), 'secrets were rotated');
    }

    public function test_wrong_token_unknown_row_and_legacy_shape_do_not_resume(): void
    {
        $cookie = $this->devices->establish(new FakeSession(), self::device('10.0.0.1'), self::USER, remember: true);

        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), Recaller::forDevice($cookie->deviceSessionId(), 'guess')));
        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), Recaller::forDevice(str_repeat('0', 32), $cookie->token())));
        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), Recaller::make(self::USER, $cookie->token())));
    }

    public function test_a_device_that_was_not_remembered_cannot_be_resumed(): void
    {
        $session = new FakeSession();
        self::assertNull($this->devices->establish($session, self::device('10.0.0.1'), self::USER));

        $row = $this->rows()[0];
        // Even someone holding the device token cannot turn it into remember-me.
        $forged = Recaller::forDevice((string) $row['session_id'], (string) $session->get(DeviceSessionService::SESSION_DEVICE_TOKEN));
        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), $forged));
    }

    public function test_signing_out_other_devices_ends_their_remember_me(): void
    {
        $here = new FakeSession();
        $this->devices->establish($here, self::device('10.0.0.1'), self::USER, remember: true);
        $other = $this->devices->establish(new FakeSession(), self::device('10.0.0.2'), self::USER, remember: true);

        $this->devices->revokeOthers($here, self::device('10.0.0.1'), self::USER);

        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.2'), $other));
        self::assertTrue($this->devices->verify($here, self::device('10.0.0.1')));
    }

    public function test_rotating_this_devices_cookie_retires_the_old_copy_and_never_remembers_an_unremembered_one(): void
    {
        $here = new FakeSession();
        $cookie = $this->devices->establish($here, self::device('10.0.0.1'), self::USER, remember: true);

        $rotated = $this->devices->rotateRemember($here);
        self::assertNotNull($rotated);
        self::assertNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), $cookie));
        self::assertNotNull($this->devices->resume(new FakeSession(), self::device('10.0.0.1'), $rotated));

        $plain = new FakeSession();
        $this->devices->establish($plain, self::device('10.0.0.3'), self::USER);
        self::assertNull($this->devices->rotateRemember($plain));
    }

    // ── Row lifetimes ───────────────────────────────────────────────────────

    public function test_a_row_that_was_not_remembered_lives_as_long_as_the_session(): void
    {
        $this->devices->establish(new FakeSession(), self::device('10.0.0.1'), self::USER);
        $this->devices->establish(new FakeSession(), self::device('10.0.0.2'), self::USER, remember: true);

        [$plain, $remembered] = $this->rows();
        self::assertEqualsWithDelta(self::SESSION_TTL + 300, $this->secondsUntil((string) $plain['expires_at']), 5);
        self::assertEqualsWithDelta(30 * 86400, $this->secondsUntil((string) $remembered['expires_at']), 5);
    }

    public function test_an_old_thirty_day_row_converges_to_the_session_lifetime_on_its_first_touch(): void
    {
        $session = new FakeSession();
        $this->devices->establish($session, self::device('10.0.0.1'), self::USER);
        // As a row opened before this change looks: 30 days, last seen long ago.
        $this->db->execute("UPDATE auth_sessions SET expires_at = :e, last_seen_at = :s", [
            'e' => (new \DateTimeImmutable('+30 days'))->format('Y-m-d H:i:s'),
            's' => (new \DateTimeImmutable('-1 hour'))->format('Y-m-d H:i:s'),
        ]);

        self::assertTrue($this->devices->verify($session, self::device('10.0.0.1')));
        self::assertEqualsWithDelta(self::SESSION_TTL + 300, $this->secondsUntil((string) $this->rows()[0]['expires_at']), 5);
    }

    public function test_a_verify_inside_the_touch_interval_writes_nothing(): void
    {
        $session = new FakeSession();
        $this->devices->establish($session, self::device('10.0.0.1'), self::USER);
        $before = $this->rows()[0];

        $this->devices->verify($session, self::device('10.0.0.1'));

        self::assertSame($before, $this->rows()[0]);
    }

    public function test_signing_in_again_in_the_same_browser_closes_the_earlier_row(): void
    {
        $session = new FakeSession();
        $this->devices->establish($session, self::device('10.0.0.1'), self::USER);
        $this->devices->establish($session, self::device('10.0.0.1'), self::USER);

        $live = array_filter($this->rows(), static fn (array $r): bool => $r['revoked_at'] === null);
        self::assertCount(1, $live);
    }

    public function test_a_failed_check_keeps_a_remembered_row_for_its_cookie_but_revokes_a_plain_one(): void
    {
        $remembered = new FakeSession();
        $cookie = $this->devices->establish($remembered, self::device('10.0.0.1'), self::USER, remember: true);
        $plain = new FakeSession();
        $this->devices->establish($plain, self::device('10.0.0.2'), self::USER);

        // e.g. a new IP: the session fails its fingerprint and is released.
        self::assertFalse($this->devices->verify($remembered, self::device('10.9.9.9')));
        $this->devices->release($remembered);
        $this->devices->release($plain);

        self::assertNotNull($this->devices->resume(new FakeSession(), self::device('10.9.9.9'), $cookie), 'remember-me survives a network change');
        self::assertNotNull($this->rows()[1]['revoked_at'], 'the plain row is closed');
    }

    public function test_the_device_list_leaves_out_sign_ins_that_lapsed(): void
    {
        $current = new FakeSession();
        $this->devices->establish($current, self::device('10.0.0.1'), self::USER);
        $this->devices->establish(new FakeSession(), self::device('10.0.0.2'), self::USER, remember: true);
        $this->devices->establish(new FakeSession(), self::device('10.0.0.3'), self::USER);
        // The third sign-in lapsed: last seen three hours ago, a 30-day expiry from before.
        $this->db->execute("UPDATE auth_sessions SET last_seen_at = :s, expires_at = :e WHERE ip = '10.0.0.3'", [
            's' => (new \DateTimeImmutable('-3 hours'))->format('Y-m-d H:i:s'),
            'e' => (new \DateTimeImmutable('+29 days'))->format('Y-m-d H:i:s'),
        ]);

        $listed = $this->devices->listDevices(self::USER, $current);

        $ips = array_map(static fn (array $d): string => (string) $d['ip'], $listed);
        sort($ips); // same-second rows have no defined order
        self::assertSame(['10.0.0.1', '10.0.0.2'], $ips, 'current + remembered, not the lapsed one');
        foreach ($listed as $device) {
            self::assertArrayNotHasKey('token_hash', $device);
            self::assertArrayNotHasKey('remember_hash', $device);
        }
    }

    // ── Before the migration ────────────────────────────────────────────────

    public function test_without_the_remember_column_sign_in_still_works_and_remember_me_goes_legacy(): void
    {
        $this->useDatabase(migrated: false);
        $session = new FakeSession();

        $cookie = $this->devices->establish($session, self::device('10.0.0.1'), self::USER, remember: true);

        self::assertNull($cookie, 'caller falls back to the per-user token');
        self::assertCount(1, $this->rows(), 'the device row is still opened');
        self::assertTrue($this->devices->verify($session, self::device('10.0.0.1')));
        self::assertSame([], array_diff(['10.0.0.1'], array_map(static fn (array $d) => $d['ip'], $this->devices->listDevices(self::USER, $session))));
        self::assertNull($this->devices->rotateRemember($session));
        $this->devices->release($session); // revokes, no error
        self::assertNotNull($this->rows()[0]['revoked_at']);
    }

    // ── The cookie value ────────────────────────────────────────────────────

    public function test_recaller_shapes(): void
    {
        $device = Recaller::forDevice('abc123', 'tok');
        self::assertSame('d:abc123|tok', $device->value());
        self::assertTrue($device->valid());
        self::assertTrue($device->isDevice());
        self::assertSame('abc123', $device->deviceSessionId());
        self::assertSame('tok', $device->token());

        $legacy = new Recaller('user-1|tok');
        self::assertTrue($legacy->valid());
        self::assertFalse($legacy->isDevice());
        self::assertSame('', $legacy->deviceSessionId());

        self::assertFalse((new Recaller('d:|tok'))->valid(), 'a device cookie with no device id');
    }
}
