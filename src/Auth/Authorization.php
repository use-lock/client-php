<?php

declare(strict_types=1);

namespace Lock\Client\Auth;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lock\Client\Auth\Tokens\IdTokenValidator;
use Lock\Client\Auth\Tokens\TokenClient;
use Lock\Client\OpenApi\Auth\Api\AuthorizationApi;
use Lock\Client\OpenApi\Auth\Api\LogoutApi;
use Lock\Client\OpenApi\Auth\Configuration;

/**
 * The authorization code flow with PKCE and the RP-initiated logout URL.
 */
class Authorization
{
    public function __construct(
        private readonly Configuration $config,
        private readonly TokenClient $tokens,
        private readonly IdTokenValidator $idTokens,
        private readonly string $clientId,
        private readonly string $redirectUri,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $parameters  Further AuthorizationApi::authorizeRequest() arguments (prompt, maxAge, resource, ...).
     */
    public function begin(array $scopes = ['openid'], array $parameters = []): AuthorizationRequest
    {
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $encoder = new JoseEncoder;
        $verifier = $encoder->base64UrlEncode(random_bytes(32));

        $request = new AuthorizationApi(config: $this->config)->authorizeRequest(...[
            ...$parameters,
            'clientId' => $this->clientId,
            'responseType' => 'code',
            'codeChallenge' => $encoder->base64UrlEncode(hash('sha256', $verifier, true)),
            'codeChallengeMethod' => 'S256',
            'redirectUri' => $this->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
        ]);

        return new AuthorizationRequest((string) $request->getUri(), $state, $nonce, $verifier);
    }

    /**
     * @param  array<string, mixed>  $query  The callback's query parameters.
     */
    public function complete(AuthorizationRequest $request, array $query): TokenSet
    {
        if (isset($query['error'])) {
            $error = is_string($query['error']) ? $query['error'] : 'unknown';

            throw new OidcException("The provider returned an authorization error [{$error}].");
        }

        if (! is_string($query['state'] ?? null) || ! hash_equals($request->state, $query['state'])) {
            throw new OidcException('The OIDC state parameter did not match.');
        }

        if (! is_string($query['code'] ?? null) || $query['code'] === '') {
            throw new OidcException('The provider did not return an authorization code.');
        }

        $tokens = $this->tokens->authorizationCode($query['code'], $this->redirectUri, $request->codeVerifier);

        if ($tokens->idToken === null) {
            throw new OidcException('The token response did not include an id_token.');
        }

        return $tokens->withClaims($this->idTokens->validate($tokens->idToken, $request->nonce));
    }

    public function logoutUrl(?string $idToken = null, ?string $postLogoutRedirectUri = null, ?string $state = null): string
    {
        return (string) new LogoutApi(config: $this->config)
            ->logoutRequest($idToken, $this->clientId, $postLogoutRedirectUri, $state)
            ->getUri();
    }
}
