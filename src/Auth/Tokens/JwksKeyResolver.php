<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\ProviderException;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;
use Lock\Client\OpenApi\Auth\ApiException;
use phpseclib3\Crypt\RSA;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * The realm's RSA signing keys as PEMs by kid, cached as a plain array.
 */
class JwksKeyResolver
{
    /** @var array<string, string>|null */
    private ?array $keys = null;

    public function __construct(
        private readonly DiscoveryApi $discovery,
        private readonly ?CacheInterface $cache = null,
        private readonly int $ttl = 3600,
    ) {}

    /**
     * An unknown kid refetches the JWKS once, so rotated keys are picked up.
     */
    public function publicKey(string $kid): string
    {
        $keys = $this->keys ?? $this->cache?->get($this->cacheKey());

        if (! is_array($keys) || ! isset($keys[$kid])) {
            $keys = $this->fetch();
        }

        return ($this->keys = $keys)[$kid] ?? throw new OidcException("No JWKS key matches the token kid [{$kid}].");
    }

    /**
     * @return array<string, string>
     */
    private function fetch(): array
    {
        try {
            $jwks = $this->discovery->getJsonWebKeySet()->getKeys() ?? [];
        } catch (ApiException $e) {
            throw new ProviderException('The JWKS could not be fetched.', $e->getCode() ?: null, previous: $e);
        }

        $keys = [];

        foreach ($jwks as $jwk) {
            try {
                $keys[$jwk->getKid()] = (string) RSA::loadFormat('JWK', (string) json_encode($jwk))->toString('PKCS8');
            } catch (Throwable $e) {
                throw new OidcException("The JWKS key [{$jwk->getKid()}] is not a valid RSA key.", 0, $e);
            }
        }

        $this->cache?->set($this->cacheKey(), $keys, $this->ttl);

        return $keys;
    }

    private function cacheKey(): string
    {
        return 'lock.jwks.'.sha1($this->discovery->getConfig()->getHost());
    }
}
