<?php

declare(strict_types=1);

namespace Lock\Client\Auth;

use Throwable;

/**
 * A request to the provider failed: it rejected the request, failed itself,
 * or no response arrived. Callers that must tell a revoked session from an
 * outage check isTransient() before discarding tokens.
 */
class ProviderException extends OidcException
{
    /**
     * @param  int|null  $status  The HTTP status, or null when no response arrived.
     * @param  string|null  $error  The OAuth error code of the response, e.g. `invalid_grant`.
     */
    public function __construct(
        string $message,
        public readonly ?int $status = null,
        public readonly ?string $error = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /**
     * Whether retrying may succeed: nothing came back, the provider failed,
     * or it throttled the request. A rejection stays a rejection.
     */
    public function isTransient(): bool
    {
        return $this->status === null || $this->status >= 500 || $this->status === 429;
    }
}
