<?php

declare(strict_types=1);

use Lock\Client\OpenApi\Auth\Api\TokensApi;
use Lock\Client\OpenApi\Auth\Model\AuthorizationCodeRequest;
use Lock\Client\OpenApi\Auth\Model\ClientCredentialsRequest;
use Lock\Client\OpenApi\Auth\Model\RefreshTokenRequest;
use Lock\Client\OpenApi\Auth\Model\TokenExchangeRequest;
use Lock\Client\OpenApi\Auth\Model\UserInfo;

it('rejects invalid grant requests before sending HTTP', function (Closure $create) {
    expect(fn () => (new TokensApi)->issueTokenRequest($create()))->toThrow(InvalidArgumentException::class);
})->with([
    'missing authorization code' => [fn () => new AuthorizationCodeRequest(['codeVerifier' => str_repeat('a', 43)])],
    'missing verifier' => [fn () => new AuthorizationCodeRequest(['code' => 'code'])],
    'short verifier' => [fn () => new AuthorizationCodeRequest(['code' => 'code', 'codeVerifier' => 'short'])],
    'long verifier' => [fn () => new AuthorizationCodeRequest(['code' => 'code', 'codeVerifier' => str_repeat('a', 129)])],
    'invalid verifier character' => [fn () => new AuthorizationCodeRequest(['code' => 'code', 'codeVerifier' => str_repeat('+', 43)])],
    'invalid verifier type' => [fn () => new AuthorizationCodeRequest(['code' => 'code', 'codeVerifier' => []])],
    'missing refresh token' => [fn () => new RefreshTokenRequest],
    'missing exchange target' => [fn () => new TokenExchangeRequest(['subjectToken' => 'token'])],
    'missing subject token' => [fn () => new TokenExchangeRequest(['audience' => 'api'])],
    'wrong grant type' => [fn () => new ClientCredentialsRequest(['grantType' => 'refresh_token'])],
    'wrong subject token type' => [fn () => new TokenExchangeRequest(['subjectToken' => 'token', 'audience' => 'api', 'subjectTokenType' => 'invalid'])],
    'non-list resources' => [fn () => new ClientCredentialsRequest(['resource' => ['api' => 'https://api.example']])],
    'non-string resource' => [fn () => new ClientCredentialsRequest(['resource' => [42]])],
]);

it('exchanges tokens using a resource target without an audience', function () {
    $request = (new TokensApi)->issueTokenRequest(new TokenExchangeRequest(['subjectToken' => 'token', 'resource' => 'https://api.example']));

    parse_str((string) $request->getBody(), $form);
    expect($form)->toEqual([
        'resource' => 'https://api.example',
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token' => 'token',
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
    ]);
});

it('validates grants again after mutation', function () {
    $grant = new RefreshTokenRequest(['refreshToken' => 'token']);
    $grant['refreshToken'] = null;

    expect(fn () => (new TokensApi)->issueTokenRequest($grant))->toThrow(InvalidArgumentException::class);
});

it('only accepts the generated grant variants', function () {
    expect(fn () => (new TokensApi)->issueTokenRequest(new UserInfo))->toThrow(TypeError::class);
});
