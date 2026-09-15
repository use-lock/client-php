<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\TokenSet;
use Lock\Client\OpenApi\Auth\Api\TokensApi;
use Lock\Client\OpenApi\Auth\ApiException;
use Lock\Client\OpenApi\Auth\Configuration;
use Lock\Client\OpenApi\Auth\Model\AuthorizationCodeRequest;
use Lock\Client\OpenApi\Auth\Model\ClientCredentialsRequest;
use Lock\Client\OpenApi\Auth\Model\OAuthError;
use Lock\Client\OpenApi\Auth\Model\RefreshTokenRequest;
use Lock\Client\OpenApi\Auth\Model\TokenExchangeRequest;
use Lock\Client\OpenApi\Auth\Model\TokenResponse;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;

/**
 * Token grants against the realm's token endpoint. The client authenticates
 * with client_secret_post, or client_secret_basic when $basicAuth is set.
 */
class TokenClient
{
    private readonly TokensApi $api;

    public function __construct(
        Configuration $config,
        private readonly string $clientId,
        #[SensitiveParameter] private readonly ?string $clientSecret = null,
        ClientInterface $http = new Client,
        private readonly ?CacheInterface $cache = null,
        private readonly bool $basicAuth = false,
    ) {
        // Lock form-urlencodes the client id and secret before building the Basic credentials.
        $this->api = new TokensApi($http, $basicAuth
            ? (clone $config)->setUsername(urlencode($clientId))->setPassword(urlencode((string) $clientSecret))
            : $config);
    }

    public function authorizationCode(string $code, string $redirectUri, string $codeVerifier): TokenSet
    {
        return $this->grant(new AuthorizationCodeRequest([
            ...$this->credentials(),
            'code' => $code,
            'redirectUri' => $redirectUri,
            'codeVerifier' => $codeVerifier,
        ]));
    }

    /**
     * A response without a refresh_token keeps the one that was used.
     *
     * @param  list<string>|null  $scopes
     */
    public function refresh(#[SensitiveParameter] string $refreshToken, ?array $scopes = null): TokenSet
    {
        return $this->grant(new RefreshTokenRequest([
            ...$this->credentials(),
            'refreshToken' => $refreshToken,
            'scope' => $this->scope($scopes),
        ]), $refreshToken);
    }

    /**
     * RFC 8693 exchange of an access token for one aimed at another audience.
     *
     * @param  list<string>|null  $scopes
     */
    public function exchange(#[SensitiveParameter] string $subjectToken, string $audience, ?array $scopes = null): TokenSet
    {
        return $this->grant(new TokenExchangeRequest([
            ...$this->credentials(),
            'subjectToken' => $subjectToken,
            'audience' => $audience,
            'scope' => $this->scope($scopes),
        ]));
    }

    /**
     * A machine token, served from the cache until 30 seconds before it expires.
     *
     * @param  string|null  $resource  RFC 8707 target resource.
     * @param  list<string>|null  $scopes
     */
    public function clientCredentials(?string $resource = null, ?array $scopes = null): TokenSet
    {
        if ($scopes) {
            $scopes = array_values(array_unique($scopes));
            sort($scopes);
        }

        $issuer = $this->api->getConfig()->getHost();
        $key = 'lock.client-credentials.'.sha1(json_encode([$issuer, $this->clientId, $resource, $scopes ?: null], JSON_THROW_ON_ERROR));

        // Cached as a plain array: caches may refuse to unserialize objects.
        $cached = $this->cache?->get($key);

        if (is_array($cached) && ! ($tokens = new TokenSet(...$cached))->isExpired()) {
            return $tokens;
        }

        $tokens = $this->grant(new ClientCredentialsRequest([
            ...$this->credentials(),
            'resource' => $resource,
            'scope' => $this->scope($scopes),
        ]));

        if ($this->cache !== null && ($ttl = $tokens->expiresAt - time() - 30) > 0) {
            $this->cache->set($key, get_object_vars($tokens), $ttl);
        }

        return $tokens;
    }

    private function grant(AuthorizationCodeRequest|RefreshTokenRequest|ClientCredentialsRequest|TokenExchangeRequest $request, ?string $refreshToken = null): TokenSet
    {
        $exception = null;

        try {
            $response = $this->api->issueToken($request);
        } catch (ApiException $exception) {
            $response = $exception->getResponseObject();
        }

        if (! $response instanceof TokenResponse || (string) $response->getAccessToken() === '') {
            $error = $response instanceof OAuthError && $response->getError() ? " [{$response->getError()}]" : '';

            throw new OidcException("The token endpoint rejected the {$request->getGrantType()} grant{$error}.", 0, $exception);
        }

        return new TokenSet(
            accessToken: $response->getAccessToken(),
            expiresAt: time() + ($response->getExpiresIn() ?? 60),
            refreshToken: $response->getRefreshToken() ?? $refreshToken,
            idToken: $response->getIdToken(),
            scopes: $response->getScope() === null ? null : array_values(array_filter(explode(' ', $response->getScope()), strlen(...))),
        );
    }

    /**
     * @return array<string, string|null>
     */
    private function credentials(): array
    {
        return $this->basicAuth ? [] : ['clientId' => $this->clientId, 'clientSecret' => $this->clientSecret];
    }

    /**
     * @param  list<string>|null  $scopes
     */
    private function scope(?array $scopes): ?string
    {
        return $scopes ? implode(' ', $scopes) : null;
    }
}
