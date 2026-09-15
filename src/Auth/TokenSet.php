<?php

declare(strict_types=1);

namespace Lock\Client\Auth;

final readonly class TokenSet
{
    /**
     * @param  list<string>|null  $scopes  Scopes the token endpoint granted, null when the response did not say.
     * @param  array<string, mixed>|null  $claims  The validated id_token claims, set after a completed login.
     */
    public function __construct(
        public string $accessToken,
        public int $expiresAt,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public ?array $scopes = null,
        public ?array $claims = null,
    ) {}

    public function expiresIn(): int
    {
        return max(0, $this->expiresAt - time());
    }

    /**
     * False while the granted scopes are unknown.
     */
    public function hasScope(string $scope): bool
    {
        return $this->scopes !== null && in_array($scope, $this->scopes, true);
    }

    public function isExpired(int $skew = 30): bool
    {
        return $this->expiresAt <= time() + $skew;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function withClaims(array $claims): self
    {
        return clone ($this, ['claims' => $claims]);
    }
}
