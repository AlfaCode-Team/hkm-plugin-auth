<?php

declare(strict_types=1);

namespace Plugins\Auth\API\IntegrationEvents;

use AlfacodeTeam\PhpServicePlatform\Kernel\Events\Contracts\IntegrationEventContract;

/**
 * A browser session changed hands — the two moments other plugins keep
 * per-session state around, and so must reset it.
 *
 *   auth.session.reset    a signed-out visitor opened a sign-in or sign-up page
 *                         and was given a fresh session. Payload: [].
 *   auth.session.started  a sign-in completed and the browser reached
 *                         /auth/session/start. Payload: userId, tenantId.
 *
 * Primitives only, per the integration-event rule: a listener in another plugin
 * must not need any Auth class to read it. Listeners run inside the request —
 * the bus handed to a request resolves them from that request's container — so a
 * listener may queue cookies or write the session, which is the point.
 */
final readonly class AuthSessionIntegrationEvent implements IntegrationEventContract
{
    public const string RESET   = 'auth.session.reset';
    public const string STARTED = 'auth.session.started';

    /** @param array<string, string> $payload */
    public function __construct(
        private string $name,
        private array $payload = [],
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function version(): string
    {
        return '1.0';
    }

    /** @return array<string, string> */
    public function payload(): array
    {
        return $this->payload;
    }
}
