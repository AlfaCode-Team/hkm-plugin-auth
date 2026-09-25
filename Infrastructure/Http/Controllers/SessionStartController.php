<?php

declare(strict_types=1);

namespace Plugins\Auth\Infrastructure\Http\Controllers;

use AlfacodeTeam\PhpServicePlatform\Kernel\Events\EventBus;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use Plugins\Auth\API\IntegrationEvents\AuthSessionIntegrationEvent;
use Project\Http\Controllers\ApiController;

/**
 * GET /auth/session/start?next=/somewhere — the first page view of a new session.
 *
 * A successful POST /auth/login answers with a redirect HERE rather than to the
 * destination, so the next request is the first one to run as the signed-in
 * user end to end: the session cookie is set, SessionAuthStage has attached the
 * Identity, and every after.load stage has seen it. That is the moment other
 * plugins can build their per-session state for this user — which they cannot
 * do inside the login POST itself, where the pipeline ran as a guest. This
 * controller announces it with `auth.session.started` and moves on to `next`.
 *
 * The announcement fires ONCE per sign-in. login() parks a marker in the
 * session and this pulls it, so a link to this URL on another site can bounce a
 * signed-in user through it but cannot make it reset their state again.
 */
final class SessionStartController extends ApiController
{
    /** Session marker: set by a successful login, pulled here. */
    public const string PENDING = 'auth.session.start_pending';

    public function start(): Response
    {
        $request  = $this->resolveRequest();
        $identity = $request->identity();
        $target   = self::safeTarget($request->query('next')) ?? '/';

        if ($identity !== null && !$identity->isGuest() && $this->sessionPull(self::PENDING, false) === true) {
            $container = $request->container();

            if ($container !== null && $container->has(EventBus::class)) {
                $container->make(EventBus::class)->dispatch(new AuthSessionIntegrationEvent(
                    AuthSessionIntegrationEvent::STARTED,
                    ['userId' => $identity->userId, 'tenantId' => $identity->tenantId],
                ));
            }
        }

        return Response::redirect($target)->withHeader('Cache-Control', 'no-store');
    }

    /** Where login() should send the browser: through here, on to $target. */
    public static function through(string $target): string
    {
        return '/auth/session/start?next=' . rawurlencode($target);
    }

    /**
     * A relative path only — the same open-redirect rule login() applies:
     * no absolute URL, no protocol-relative '//', no '/\' backslash trick.
     */
    public static function safeTarget(mixed $candidate): ?string
    {
        if (!is_string($candidate) || $candidate === '' || $candidate[0] !== '/'
            || str_starts_with($candidate, '//') || str_starts_with($candidate, '/\\')) {
            return null;
        }

        return $candidate;
    }
}
