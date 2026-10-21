<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Stages;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Pipelines\Http\Contracts\HttpStageContract;
use Plugins\Auth\Infrastructure\Http\Controllers\SessionStartController;

/**
 * The `guest` route filter — a page only a signed-out visitor should see.
 *
 *     { "method": "GET", "path": "/login", "handler": "…",
 *       "filters": ["guest", "fresh-session"] }
 *
 *     "filters": ["guest:/platform"]   // where a signed-in visitor goes instead
 *
 * A signed-in visitor who opens a sign-in, sign-up or forgot-password page is
 * sent on rather than shown a form. Shown it, they read it as "I was signed
 * out", go back and find themselves signed in; and a form submitted from it
 * would sign in again on top of their session (SessionAuthController::login()
 * now copes with that, but the page should not invite it).
 *
 * Where they go, first match wins:
 *
 *   1. the page's own `?redirectTo=` — the place the sign-in link meant to
 *      return to — through the same open-redirect guard the login uses;
 *   2. the filter's argument (`guest:/account`), for a project whose home for a
 *      signed-in person is not `/`;
 *   3. `/`.
 *
 * A target that is the page itself is ignored, so a mistyped argument renders
 * the page instead of looping. Only GET and HEAD are redirected: a form posting
 * from an old tab is the controller's to answer, and a redirect would drop its
 * body. A remember-me visitor counts as signed in — SessionAuthStage resurrects
 * them before route filters run. The route must load `auth.identity`
 * (directly, or through its module), or every visitor reads as a guest.
 */
final class GuestOnlyStage implements HttpStageContract
{
    public const string ALIAS = 'guest';

    public function handle(Request $request, callable $next): Response
    {
        if (!\in_array($request->method(), ['GET', 'HEAD'], true)) {
            return $next($request);
        }

        $identity = $request->identity();
        if ($identity === null || $identity->isGuest()) {
            return $next($request);
        }

        $target = self::target($request);

        return $target === null ? $next($request) : Response::redirect($target);
    }

    /** Where a signed-in visitor goes, or null to render the page after all. */
    public static function target(Request $request): ?string
    {
        $args = $request->attribute('filter_args')[self::ALIAS] ?? [];
        $home = \is_array($args) && isset($args[0]) ? trim((string) $args[0]) : '';

        foreach ([$request->query('redirectTo'), $home, '/'] as $candidate) {
            $safe = SessionStartController::safeTarget(\is_string($candidate) ? trim($candidate) : null);
            if ($safe !== null && self::pathOf($safe) !== $request->path()) {
                return $safe;
            }
        }

        return null;
    }

    private static function pathOf(string $target): string
    {
        $path = parse_url($target, PHP_URL_PATH);

        return \is_string($path) && $path !== '' ? $path : '/';
    }
}
