<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lock\Client\Auth\Discovery;
use Psr\SimpleCache\CacheInterface;

function arrayCache(): CacheInterface
{
    return new class implements CacheInterface
    {
        /** @var array<string, mixed> */
        private array $values = [];

        public function get(string $key, mixed $default = null): mixed
        {
            return $this->values[$key] ?? $default;
        }

        public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
        {
            $this->values[$key] = $value;

            return true;
        }

        public function delete(string $key): bool
        {
            unset($this->values[$key]);

            return true;
        }

        public function clear(): bool
        {
            $this->values = [];

            return true;
        }

        public function getMultiple(iterable $keys, mixed $default = null): iterable
        {
            foreach ($keys as $key) {
                yield $key => $this->get($key, $default);
            }
        }

        public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
        {
            foreach ($values as $key => $value) {
                $this->set($key, $value, $ttl);
            }

            return true;
        }

        public function deleteMultiple(iterable $keys): bool
        {
            foreach ($keys as $key) {
                $this->delete($key);
            }

            return true;
        }

        public function has(string $key): bool
        {
            return array_key_exists($key, $this->values);
        }
    };
}

/**
 * A Guzzle client answering with the given JSON bodies in order.
 *
 * @param  array<int, array<string, mixed>>  $bodies
 * @param  array<int, array<string, mixed>>  $history
 */
function jsonClient(array $bodies, array &$history = []): Client
{
    $handler = HandlerStack::create(new MockHandler(array_map(
        fn (array $body): Response => new Response(200, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR)),
        $bodies,
    )));
    $handler->push(Middleware::history($history));

    return new Client(['handler' => $handler]);
}

/**
 * @return array<string, string>
 */
function discoveryDocument(string $issuer = 'https://id.example.com'): array
{
    return [
        'issuer' => $issuer,
        'authorization_endpoint' => 'https://id.example.com/oauth/authorize',
        'token_endpoint' => 'https://id.example.com/oauth/token',
        'jwks_uri' => 'https://id.example.com/.well-known/jwks.json',
    ];
}

/**
 * Discovery for https://id.example.com serving one JWKS key list per fetch.
 *
 * @param  array<int, array<int, array<string, mixed>>>  $jwks
 * @param  array<int, array<string, mixed>>  $history
 */
function fakeDiscovery(array $jwks, array &$history = []): Discovery
{
    $bodies = [discoveryDocument(), ...array_map(fn (array $keys): array => ['keys' => $keys], $jwks)];

    return new Discovery('https://id.example.com', arrayCache(), jsonClient($bodies, $history));
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function idTokenClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'nonce' => 'the-nonce',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + 300,
    ], $overrides);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function logoutTokenClaims(array $overrides = []): array
{
    return array_merge([
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'sid' => 'sess-abc',
        'iat' => time(),
        'exp' => time() + 120,
        'jti' => 'jti-1',
        'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
    ], $overrides);
}
