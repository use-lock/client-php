<?php

declare(strict_types=1);

namespace Lock\Client\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Lock\Client\OpenApi\Auth\Model\ProviderMetadata;
use Lock\Client\OpenApi\Auth\ObjectSerializer;
use Psr\SimpleCache\CacheInterface;

/**
 * Fetches and caches an issuer's discovery document and JWKS. Both are
 * decoded arrays in the cache: the generated JsonWebKey model has no EC
 * coordinates, and the provider's jwks_uri is not necessarily the
 * generated DiscoveryApi's fixed path.
 */
class Discovery
{
    private readonly string $issuer;

    private ?ProviderMetadata $metadata = null;

    public function __construct(
        string $issuer,
        private readonly CacheInterface $cache,
        private readonly ClientInterface $http = new Client,
        private readonly int $ttl = 3600,
    ) {
        $this->issuer = rtrim($issuer, '/');
    }

    public function metadata(): ProviderMetadata
    {
        return $this->metadata ??= ObjectSerializer::deserialize($this->document(), ProviderMetadata::class);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function jwks(bool $fresh = false): array
    {
        $key = 'lock-oidc.jwks.'.sha1($this->issuer);

        if (! $fresh && is_array($keys = $this->cache->get($key))) {
            return $keys;
        }

        $keys = $this->get($this->metadata()->getJwksUri())['keys'] ?? null;

        if (! is_array($keys)) {
            throw new OidcException('The OIDC JWKS response has no keys.');
        }

        $this->cache->set($key, $keys, $this->ttl);

        return $keys;
    }

    /**
     * @return array<string, mixed>
     */
    private function document(): array
    {
        $key = 'lock-oidc.discovery.'.sha1($this->issuer);

        if (is_array($doc = $this->cache->get($key))) {
            return $doc;
        }

        $doc = $this->get($this->issuer.'/.well-known/openid-configuration');

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (! isset($doc[$required]) || ! is_string($doc[$required])) {
                throw new OidcException("The OIDC discovery document is missing [{$required}].");
            }
        }

        if (rtrim($doc['issuer'], '/') !== $this->issuer) {
            throw new OidcException('The discovery document issuer does not match the configured issuer.');
        }

        $this->cache->set($key, $doc, $this->ttl);

        return $doc;
    }

    /**
     * @return array<string, mixed>
     */
    private function get(string $url): array
    {
        try {
            $body = json_decode((string) $this->http->request('GET', $url)->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (GuzzleException|JsonException $e) {
            throw new OidcException("The OIDC request to [{$url}] failed.", 0, $e);
        }

        if (! is_array($body)) {
            throw new OidcException("The OIDC response from [{$url}] was not a JSON object.");
        }

        return $body;
    }
}
