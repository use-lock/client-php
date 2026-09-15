<?php

declare(strict_types=1);

use Lock\Client\Auth\Tokens\TokenClient;

beforeEach(function () {
    $this->history = [];
    $this->client = fn (array $responses, bool $basicAuth = false) => new TokenClient(
        realm(), 'client-123', 'se:cret', jsonClient($responses, $this->history), arrayCache(), $basicAuth,
    );
});

it('keeps the used refresh token when the response has none', function () {
    $tokens = ($this->client)([['access_token' => 'fresh', 'token_type' => 'Bearer', 'expires_in' => 300]])->refresh('the-refresh-token');

    expect($tokens->accessToken)->toBe('fresh')
        ->and($tokens->refreshToken)->toBe('the-refresh-token');
});

it('serves client credentials tokens from the cache', function () {
    $client = ($this->client)([['access_token' => 'machine', 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'a b']]);

    $first = $client->clientCredentials('https://api.example.com', ['b', 'a']);
    $second = $client->clientCredentials('https://api.example.com', ['a', 'b']);

    expect($second)->toEqual($first)
        ->and($second->scopes)->toBe(['a', 'b'])
        ->and($this->history)->toHaveCount(1);
});

it('authenticates with client_secret_post or client_secret_basic', function (bool $basicAuth, string $authorization, array $credentials) {
    ($this->client)([['access_token' => 'machine', 'token_type' => 'Bearer', 'expires_in' => 300]], $basicAuth)->clientCredentials();

    expect($this->history[0]['request']->getHeaderLine('Authorization'))->toBe($authorization)
        ->and(formFields($this->history[0]))->toBe([...$credentials, 'grant_type' => 'client_credentials']);
})->with([
    'post' => [false, '', ['client_id' => 'client-123', 'client_secret' => 'se:cret']],
    'basic' => [true, 'Basic '.base64_encode('client-123:se%3Acret'), []],
]);
