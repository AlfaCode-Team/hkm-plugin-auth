<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Controllers;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use Plugins\Pageflow\Http\PageflowResponder;
use Project\Http\Controllers\Concerns\InteractsWithGraphSeo;

/**
 * Pageflow (SPA) pages shipped BY the Auth plugin — the server half of
 * `ui/site/Pages/Auth/*`.
 *
 * The plugin owns authentication, so it also owns the default sign-in screen:
 * enable the plugin and `GET /auth/login` renders a working, CSRF-correct login
 * page with no project code at all. A project that wants a different look
 * declares its own `Pages/Auth/Login.tsx` (project pages are spread first in the
 * surface glob, so they win) or disables this route in `proj.json`
 * `routePolicy.disable`.
 *
 * This controller renders and does NOT authenticate. Credentials go to
 * `SessionAuthController@login` (`POST /auth/login`), which already exists and
 * is what the shipped form posts to.
 *
 * SEO — a sign-in page must never be indexed, so it always gets `seoPrivate()`:
 * a correct <title> plus noindex,nofollow, and no graph cost. Both SEO helpers
 * return '' on a Pageflow XHR navigation, so SPA hops pay nothing.
 */
final class AuthPageController
{
    use InteractsWithGraphSeo;

    public function __construct(
        private readonly PageflowResponder $pageflow,
    ) {
    }

    /** GET /auth/login → component "Auth/Login". */
    public function loginPage(Request $request): Response
    {
        // Already signed in? Showing the form invites a pointless re-login and,
        // worse, a second `attempt()` that rotates the session id under a user
        // who was authenticated the whole time. Send them where they were going.
        $identity = $request->identity();
        if ($identity !== null && !$identity->isGuest()) {
            return Response::redirect($this->relativePath($request->query('redirectTo')) ?? '/');
        }

        // The SURFACE this page renders into. Defaults to 'admin', which is the
        // conventional name, but a project may call its console anything —
        // hkmvote's is 'organiser' — and a wrong name here is a 500 (the Vite
        // manifest for that surface does not exist), not a graceful fallback.
        return $this->pageflow->render($request, 'Auth/Login', env('AUTH_PAGE_SURFACE', 'admin'), [
            // Only a RELATIVE path is passed through. `redirectTo` is attacker-
            // controlled (it is a query parameter on a public page), and handing
            // an absolute URL to the form would turn the login screen into an
            // open redirect. The login endpoint applies the same guard again —
            // this one only keeps a bad value from ever reaching the client.
            'redirectTo'        => $this->relativePath($request->query('redirectTo')),
            'identifier'        => (string) ($request->query('identifier') ?? ''),
            'notice'            => $this->notice((string) ($request->query('reason') ?? '')),
            'appName'           => env('APP_NAME', ''),
            'registerUrl'       => env('AUTH_REGISTER_URL', '/register'),
            // No default: this plugin ships POST /auth/password/forgot (the
            // endpoint) but no GET page for it, and linking an <a href> at a
            // POST-only route just 405s. Empty hides the link.
            'forgotPasswordUrl' => env('AUTH_FORGOT_PASSWORD_URL', ''),
            'seoHead'           => $this->seoPrivate('Sign in', request: $request),
        ]);
    }

    /**
     * Keep same-origin relative paths only.
     *
     * Rejects absolute URLs, scheme-relative `//evil.test` and anything with a
     * backslash (which some browsers normalise to `/`).
     */
    private function relativePath(mixed $value): ?string
    {
        $path = \is_string($value) ? \trim($value) : '';

        if ($path === '' || $path[0] !== '/') {
            return null;
        }
        if (str_starts_with($path, '//') || str_contains($path, '\\')) {
            return null;
        }

        return $path;
    }

    /** Map a `?reason=` code to a human sentence. Unknown codes show nothing. */
    private function notice(string $reason): ?string
    {
        return match ($reason) {
            'expired'      => 'Your session expired. Please sign in again.',
            'unauthorized' => 'Please sign in to continue.',
            'logged_out'   => 'You have been signed out.',
            default        => null,
        };
    }
}
