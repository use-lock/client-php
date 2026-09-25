<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Lock\Client\Auth\ProviderException;
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

it('tells a rejected grant from a provider that failed or could not be reached', function (Response|ConnectException $response, ?int $status, ?string $error, bool $transient, string $message) {
    $client = new TokenClient(realm(), 'client-123', 'se:cret', new Client(['handler' => HandlerStack::create(new MockHandler([$response]))]));

    try {
        $client->refresh('the-refresh-token');
        $this->fail('The grant did not fail.');
    } catch (ProviderException $exception) {
        expect($exception->status)->toBe($status)
            ->and($exception->error)->toBe($error)
            ->and($exception->isTransient())->toBe($transient)
            ->and($exception->getMessage())->toContain($message);
    }
})->with([
    'rejected' => [new Response(400, ['Content-Type' => 'application/json'], '{"error":"invalid_grant"}'), 400, 'invalid_grant', false, 'rejected the refresh_token grant [invalid_grant]'],
    'provider failure' => [new Response(503, [], 'down'), 503, null, true, 'failed on the refresh_token grant'],
    'throttled' => [new Response(429, [], 'slow down'), 429, null, true, 'rejected the refresh_token grant'],
    'unreachable' => [new ConnectException('Connection refused', new Request('POST', 'https://id.example.com/oauth/token')), null, null, true, 'could not be reached for the refresh_token grant'],
]);
