<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lock\Client\Auth\Authorization;
use Lock\Client\Auth\AuthorizationRequest;
use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\IdTokenValidator;
use Lock\Client\Auth\Tokens\JwksKeyResolver;
use Lock\Client\Auth\Tokens\TokenClient;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;

beforeEach(function () {
    $this->provider = new FakeProvider;
    $this->history = [];
    $this->authorization = function (array $responses = []) {
        $http = jsonClient($responses, $this->history);

        return new Authorization(
            realm(),
            new TokenClient(realm(), 'client-123', 'the-secret', $http),
            new IdTokenValidator(new JwksKeyResolver(new DiscoveryApi($http, realm())), 'client-123'),
            'client-123',
            'https://app.example.com/callback',
        );
    };
    $this->request = new AuthorizationRequest('https://id.example.com/oauth/authorize', 'the-state', 'the-nonce', str_repeat('v', 43));
});

it('builds the authorization URL with a PKCE challenge', function () {
    $request = ($this->authorization)()->begin(['openid', 'email'], ['prompt' => 'login']);

    [$endpoint, $query] = explode('?', $request->url, 2);
    parse_str($query, $parameters);

    expect($endpoint)->toBe('https://id.example.com/oauth/authorize')
        ->and($parameters)->toMatchArray([
            'client_id' => 'client-123',
            'response_type' => 'code',
            'redirect_uri' => 'https://app.example.com/callback',
            'scope' => 'openid email',
            'state' => $request->state,
            'nonce' => $request->nonce,
            'prompt' => 'login',
            'code_challenge' => new JoseEncoder()->base64UrlEncode(hash('sha256', $request->codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ]);
});

it('exchanges the callback code and validates the id token', function () {
    $tokens = ($this->authorization)([
        ['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 300, 'refresh_token' => 'rt', 'id_token' => $this->provider->idToken(idTokenClaims(), 'kid')],
        $this->provider->jwks('kid'),
    ])->complete($this->request, ['state' => 'the-state', 'code' => 'the-code']);

    expect((string) $this->history[0]['request']->getUri())->toBe('https://id.example.com/oauth/token')
        ->and(formFields($this->history[0]))->toBe([
            'client_id' => 'client-123',
            'client_secret' => 'the-secret',
            'grant_type' => 'authorization_code',
            'code' => 'the-code',
            'code_verifier' => $this->request->codeVerifier,
            'redirect_uri' => 'https://app.example.com/callback',
        ])
        ->and($tokens->accessToken)->toBe('at')
        ->and($tokens->refreshToken)->toBe('rt')
        ->and($tokens->claims['sub'])->toBe('42');
});

it('rejects an invalid callback', function (array $query, array $responses, string $message) {
    expect(fn () => ($this->authorization)($responses)->complete($this->request, $query))
        ->toThrow(OidcException::class, $message);
})->with([
    'provider error' => [['error' => 'access_denied', 'state' => 'the-state'], [], 'authorization error [access_denied]'],
    'state mismatch' => [['state' => 'other', 'code' => 'the-code'], [], 'state parameter did not match'],
    'missing code' => [['state' => 'the-state'], [], 'did not return an authorization code'],
    'missing id_token' => [['state' => 'the-state', 'code' => 'the-code'], [['access_token' => 'at', 'token_type' => 'Bearer']], 'did not include an id_token'],
    'token endpoint error' => [
        ['state' => 'the-state', 'code' => 'the-code'],
        [new Response(400, ['Content-Type' => 'application/json'], '{"error":"invalid_grant","error_description":"Expired code"}')],
        'rejected the authorization_code grant [invalid_grant]',
    ],
]);

it('builds the logout URL', function () {
    expect(($this->authorization)()->logoutUrl('the-id-token', 'https://app.example.com/', 'xyz'))
        ->toBe('https://id.example.com/oauth/logout?id_token_hint=the-id-token&client_id=client-123&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F&state=xyz');
});
