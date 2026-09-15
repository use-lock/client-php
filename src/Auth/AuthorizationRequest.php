<?php

declare(strict_types=1);

namespace Lock\Client\Auth;

/**
 * The redirect URL plus the secrets the callback is checked against; persist
 * it between the redirect and the callback.
 */
final readonly class AuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $state,
        public string $nonce,
        public string $codeVerifier,
    ) {}
}
