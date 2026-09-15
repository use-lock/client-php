<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;
use Lock\Client\OpenApi\Auth\Api\TokensApi;
use Lock\Client\OpenApi\Auth\Api\UserInfoApi;
use Lock\Client\OpenApi\Auth\ApiException;
use Lock\Client\OpenApi\Auth\Configuration;
use Lock\Client\OpenApi\Auth\Model\AuthorizationCodeRequest;
use Lock\Client\OpenApi\Auth\Model\ClientCredentialsRequest;
use Lock\Client\OpenApi\Auth\Model\RefreshTokenRequest;
use Lock\Client\OpenApi\Auth\Model\TokenExchangeRequest;

it('posts client credentials as form data to the configured realm host', function (string|array $resource) {
    $history = [];
    $handler = HandlerStack::create(new MockHandler([new Response(200, ['Content-Type' => 'application/json'],
        '{"access_token":"token","token_type":"Bearer","expires_in":300}'
    )]));
    $handler->push(Middleware::history($history));
    $api = new TokensApi(new Client(['handler' => $handler]), (new Configuration)->setHost('https://realm.example'));

    $response = $api->issueToken(new ClientCredentialsRequest(['clientId' => 'client', 'clientSecret' => 'secret+&=', 'resource' => $resource]));

    $request = $history[0]['request'];
    expect((string) $request->getUri())->toBe('https://realm.example/oauth/token');
    expect($request->getMethod())->toBe('POST');
    expect($request->getHeaderLine('Content-Type'))->toBe('application/x-www-form-urlencoded');
    parse_str((string) $request->getBody(), $form);
    expect($form)->toEqual(['client_id' => 'client', 'client_secret' => 'secret+&=', 'resource' => $resource, 'grant_type' => 'client_credentials']);
    expect($response->getAccessToken())->toBe('token');
    expect($response->getExpiresIn())->toBe(300);
})->with([
    'single resource' => ['https://lock.example/api'],
    'multiple resources' => [['https://lock.example/api', 'https://service.example']],
]);

it('sends authorization code and refresh grants with basic authentication', function (AuthorizationCodeRequest|RefreshTokenRequest|TokenExchangeRequest $grant, array $fields) {
    $api = new TokensApi(config: (new Configuration)->setHost('https://realm.example')->setUsername('client')->setPassword('secret'));

    $request = $api->issueTokenRequest($grant);

    expect($request->getHeaderLine('Authorization'))->toBe('Basic '.base64_encode('client:secret'));
    parse_str((string) $request->getBody(), $form);
    expect($form)->toEqual($fields);
})->with([
    'authorization code' => [new AuthorizationCodeRequest(['code' => 'code+&=', 'codeVerifier' => str_repeat('a', 43), 'redirectUri' => 'https://app.example/callback']), ['grant_type' => 'authorization_code', 'code' => 'code+&=', 'code_verifier' => str_repeat('a', 43), 'redirect_uri' => 'https://app.example/callback']],
    'refresh' => [new RefreshTokenRequest(['refreshToken' => 'refresh+&=']), ['grant_type' => 'refresh_token', 'refresh_token' => 'refresh+&=']],
    'exchange' => [new TokenExchangeRequest(['subjectToken' => 'subject', 'audience' => 'api', 'requestedTokenType' => 'urn:ietf:params:oauth:token-type:access_token']), ['grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token' => 'subject', 'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token', 'audience' => 'api', 'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token']],
]);

it('decodes discovery metadata from the configured host', function () {
    $history = [];
    $handler = HandlerStack::create(new MockHandler([new Response(200, ['Content-Type' => 'application/json'],
        '{"issuer":"https://realm.example","authorization_endpoint":"https://realm.example/oauth/authorize","token_endpoint":"https://realm.example/oauth/token","jwks_uri":"https://realm.example/.well-known/jwks.json","claims_parameter_supported":false,"backchannel_logout_supported":true}'
    )]));
    $handler->push(Middleware::history($history));
    $api = new DiscoveryApi(new Client(['handler' => $handler]), (new Configuration)->setHost('https://realm.example'));

    $metadata = $api->getProviderMetadata();

    expect((string) $history[0]['request']->getUri())->toBe('https://realm.example/.well-known/openid-configuration');
    expect($metadata->getIssuer())->toBe('https://realm.example');
    expect($metadata->getTokenEndpoint())->toBe('https://realm.example/oauth/token');
    expect($metadata->getClaimsParameterSupported())->toBeFalse();
    expect($metadata->getBackchannelLogoutSupported())->toBeTrue();
});

it('retains OAuth error details', function () {
    $api = new TokensApi(new Client(['handler' => HandlerStack::create(new MockHandler([
        new Response(400, ['Content-Type' => 'application/json'], '{"error":"invalid_grant","error_description":"Expired code"}'),
    ]))]));

    try {
        $api->issueToken(new AuthorizationCodeRequest(['code' => 'expired', 'codeVerifier' => str_repeat('a', 43)]));
        test()->fail('Expected an OAuth error.');
    } catch (ApiException $exception) {
        expect($exception->getCode())->toBe(400);
        expect($exception->getResponseObject()->getError())->toBe('invalid_grant');
        expect($exception->getResponseObject()->getErrorDescription())->toBe('Expired code');
    }
});

it('preserves custom userinfo claims alongside typed standard claims', function () {
    $body = '{"sub":"user-123","email":"user@example.com","email_verified":true,"roles":["editor"],"team":{"slug":"engineering"}}';
    $api = new UserInfoApi(new Client(['handler' => HandlerStack::create(new MockHandler([
        new Response(200, ['Content-Type' => 'application/json'], $body),
    ]))]));

    $user = $api->getUserInfo();

    expect($user->getSub())->toBe('user-123');
    expect($user->getEmailVerified())->toBeTrue();
    expect($user['roles'])->toBe(['editor']);
    expect(json_decode(json_encode($user, JSON_THROW_ON_ERROR), true))->toEqual(json_decode($body, true));
});
