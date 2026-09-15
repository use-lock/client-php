<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lock\Client\Auth\Tokens\JwksKeyResolver;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;
use Lock\Client\OpenApi\Auth\Configuration;
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
            return [];
        }

        public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
        {
            return false;
        }

        public function deleteMultiple(iterable $keys): bool
        {
            return false;
        }

        public function has(string $key): bool
        {
            return array_key_exists($key, $this->values);
        }
    };
}

/**
 * The realm https://id.example.com.
 */
function realm(): Configuration
{
    return new Configuration()->setHost('https://id.example.com');
}

/**
 * A Guzzle client answering with the given JSON bodies (or responses) in order.
 *
 * @param  array<int, array<string, mixed>|Response>  $bodies
 * @param  array<int, array<string, mixed>>  $history
 */
function jsonClient(array $bodies, array &$history = []): Client
{
    $handler = HandlerStack::create(new MockHandler(array_map(
        fn (array|Response $body): Response => $body instanceof Response ? $body : new Response(200, ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR)),
        $bodies,
    )));
    $handler->push(Middleware::history($history));

    return new Client(['handler' => $handler]);
}

/**
 * @param  array<int, array<string, mixed>>  $jwks  One JWKS document per fetch.
 * @param  array<int, array<string, mixed>>  $history
 */
function keyResolver(array $jwks, array &$history = []): JwksKeyResolver
{
    return new JwksKeyResolver(new DiscoveryApi(jsonClient($jwks, $history), realm()));
}

/**
 * @param  array<string, mixed>  $entry  A recorded history entry.
 * @return array<string, string>
 */
function formFields(array $entry): array
{
    parse_str((string) $entry['request']->getBody(), $fields);

    return $fields;
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function idTokenClaims(array $overrides = []): array
{
    return [
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'nonce' => 'the-nonce',
        'iat' => time(),
        'exp' => time() + 300,
        ...$overrides,
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function logoutTokenClaims(array $overrides = []): array
{
    return [
        'iss' => 'https://id.example.com',
        'aud' => 'client-123',
        'sub' => '42',
        'sid' => 'sess-abc',
        'iat' => time(),
        'exp' => time() + 120,
        'jti' => 'jti-1',
        'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object) []],
        ...$overrides,
    ];
}
