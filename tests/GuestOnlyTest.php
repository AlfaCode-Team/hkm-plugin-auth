<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Auth;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\TestCase;
use Plugins\Auth\Application\Ports\Authenticatable;
use Plugins\Auth\Application\Ports\StatefulGuard;
use Plugins\Auth\Infrastructure\Http\Controllers\SessionAuthController;
use Plugins\Auth\Infrastructure\Http\Stages\GuestOnlyStage;

/**
 * Signed-out-only pages, and signing in while already signed in.
 *
 * The `guest` filter sends a signed-in visitor on instead of showing them a
 * sign-in form; SessionAuthController::whenSignedIn() decides what a sign-in
 * POST from such a person means — nothing, a switch of account, or a refusal
 * that keeps the current person signed in.
 */
final class GuestOnlyTest extends TestCase
{
    // ── the `guest` filter ───────────────────────────────────────────────────

    public function test_a_signed_out_visitor_sees_the_page(): void
    {
        self::assertSame(200, $this->visit(Request::build('GET', '/login'))->getStatusCode());
    }

    public function test_a_signed_in_visitor_goes_home(): void
    {
        $response = $this->visit($this->signedIn(Request::build('GET', '/login')));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/', $response->headers->get('Location'));
    }

    public function test_the_page_s_own_redirect_to_wins(): void
    {
        $response = $this->visit($this->signedIn(Request::build('GET', '/login', query: ['redirectTo' => '/editions/7?tab=votes'])), '/platform');

        self::assertSame('/editions/7?tab=votes', $response->headers->get('Location'));
    }

    public function test_the_filter_argument_names_the_home(): void
    {
        $response = $this->visit($this->signedIn(Request::build('GET', '/login')), '/platform');

        self::assertSame('/platform', $response->headers->get('Location'));
    }

    public function test_an_off_site_redirect_to_is_ignored(): void
    {
        foreach (['https://evil.test/', '//evil.test', "/\t/evil.test", '/\\evil.test'] as $evil) {
            $response = $this->visit($this->signedIn(Request::build('GET', '/login', query: ['redirectTo' => $evil])), '/account');

            self::assertSame('/account', $response->headers->get('Location'), "redirectTo {$evil}");
        }
    }

    public function test_a_target_that_is_the_page_itself_renders_the_page_instead_of_looping(): void
    {
        $response = $this->visit($this->signedIn(Request::build('GET', '/', query: ['redirectTo' => '/'])));

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_a_form_post_is_left_to_the_controller(): void
    {
        self::assertSame(200, $this->visit($this->signedIn(Request::build('POST', '/login')))->getStatusCode());
    }

    // ── signing in while signed in ───────────────────────────────────────────

    public function test_the_same_account_again_is_nothing_to_do(): void
    {
        $guard = new FakeGuard(valid: true, matches: new FakeUser('u-1'));

        self::assertSame(SessionAuthController::SAME_ACCOUNT, SessionAuthController::whenSignedIn($guard, new FakeUser('u-1'), self::CREDENTIALS));
        self::assertSame(0, $guard->attempts, 'checked, never signed in again');
    }

    public function test_another_account_with_the_right_password_is_a_switch(): void
    {
        $guard = new FakeGuard(valid: true, matches: new FakeUser('u-2'));

        self::assertSame(SessionAuthController::OTHER_ACCOUNT, SessionAuthController::whenSignedIn($guard, new FakeUser('u-1'), self::CREDENTIALS));
        self::assertFalse($guard->loggedOut, 'deciding signs nobody out');
    }

    public function test_a_wrong_password_is_refused_and_signs_nobody_out(): void
    {
        $guard = new FakeGuard(valid: false);

        self::assertSame(SessionAuthController::REFUSED, SessionAuthController::whenSignedIn($guard, new FakeUser('u-1'), self::CREDENTIALS));
        self::assertFalse($guard->loggedOut);
        self::assertSame(1, $guard->validations, 'one check, so one wrong password counts once');
    }

    public function test_a_guard_that_cannot_say_who_matched_is_treated_as_a_switch(): void
    {
        $guard = new FakeGuardWithoutLastAttempted();

        self::assertSame(SessionAuthController::OTHER_ACCOUNT, SessionAuthController::whenSignedIn($guard, new FakeUser('u-1'), self::CREDENTIALS));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private const array CREDENTIALS = ['identifier' => 'ann@example.com', 'password' => 'secret'];

    private function visit(Request $request, ?string $home = null): Response
    {
        if ($home !== null) {
            $request = $request->withAttribute('filter_args', [GuestOnlyStage::ALIAS => [$home]]);
        }

        return (new GuestOnlyStage())->handle($request, static fn (): Response => Response::html('the page'));
    }

    private function signedIn(Request $request): Request
    {
        return $request->withIdentity(Identity::asUser('u-1', 'tenant-1'));
    }
}

final class FakeUser implements Authenticatable
{
    public function __construct(private readonly string $id) {}
    public function getAuthIdentifier(): string { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getUsername(): string { return $this->id; }
    public function getEmail(): string { return $this->id . '@example.com'; }
    public function identity(): Identity { return Identity::asUser($this->id); }
}

/** validate() answers as told and remembers who it matched, like StatefulSessionGuard. */
class FakeGuard implements StatefulGuard
{
    public int $validations = 0;
    public int $attempts = 0;
    public bool $loggedOut = false;
    private ?Authenticatable $last = null;

    public function __construct(private readonly bool $valid = true, private readonly ?Authenticatable $matches = null) {}

    public function validate(array $credentials = []): bool
    {
        $this->validations++;
        $this->last = $this->valid ? $this->matches : null;

        return $this->valid;
    }

    public function getLastAttempted(): ?Authenticatable { return $this->last; }
    public function attempt(array $credentials = [], bool $remember = false): bool { $this->attempts++; return $this->valid; }
    public function once(array $credentials = []): bool { return $this->valid; }
    public function login(Authenticatable $user, bool $remember = false): void {}
    public function loginUsingId(string $id, bool $remember = false): Authenticatable|false { return false; }
    public function onceUsingId(string $id): Authenticatable|false { return false; }
    public function viaRemember(): bool { return false; }
    public function logout(): void { $this->loggedOut = true; }
}

/** A guard with no getLastAttempted(): it can check a password but not say whose. */
final class FakeGuardWithoutLastAttempted implements StatefulGuard
{
    public function validate(array $credentials = []): bool { return true; }
    public function attempt(array $credentials = [], bool $remember = false): bool { return true; }
    public function once(array $credentials = []): bool { return true; }
    public function login(Authenticatable $user, bool $remember = false): void {}
    public function loginUsingId(string $id, bool $remember = false): Authenticatable|false { return false; }
    public function onceUsingId(string $id): Authenticatable|false { return false; }
    public function viaRemember(): bool { return false; }
    public function logout(): void {}
}
