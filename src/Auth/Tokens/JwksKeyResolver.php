<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Lock\Client\Auth\Discovery;
use Lock\Client\Auth\OidcException;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Throwable;

class JwksKeyResolver
{
    /** @var array<string, array{0: string, 1: string}> */
    private array $keysByKid = [];

    public function __construct(private readonly Discovery $discovery) {}

    /**
     * The verification material for a JWKS entry: the public key PEM and the
     * JWA algorithm it signs with.
     *
     * @return array{0: string, 1: string}
     */
    public function signingKey(string $kid): array
    {
        return $this->keysByKid[$kid] ??= $this->resolve($kid);
    }

    /**
     * An unknown kid refetches the JWKS once, so rotated keys are picked up.
     *
     * @return array{0: string, 1: string}
     */
    private function resolve(string $kid): array
    {
        return $this->findKeyInJwks($kid, $this->discovery->jwks())
            ?? $this->findKeyInJwks($kid, $this->discovery->jwks(fresh: true))
            ?? throw new OidcException("No JWKS key matches the token kid [{$kid}].");
    }

    /**
     * @param  array<int, array<string, mixed>>  $jwks
     * @return array{0: string, 1: string}|null
     */
    private function findKeyInJwks(string $kid, array $jwks): ?array
    {
        foreach ($jwks as $jwk) {
            if (($jwk['kid'] ?? null) === $kid) {
                return [$this->publicKeyPem($kid, $jwk), $this->algorithm($kid, $jwk)];
            }
        }

        return null;
    }

    /**
     * The JWK's own alg when declared, otherwise inferred from the key type.
     * Whether the algorithm is acceptable is decided by the validator.
     *
     * @param  array<string, mixed>  $jwk
     */
    private function algorithm(string $kid, array $jwk): string
    {
        $alg = $jwk['alg'] ?? null;

        if (is_string($alg) && $alg !== '') {
            return $alg;
        }

        return match (true) {
            ($jwk['kty'] ?? null) === 'RSA' => 'RS256',
            ($jwk['kty'] ?? null) === 'EC' && ($jwk['crv'] ?? null) === 'P-256' => 'ES256',
            default => throw new OidcException("The JWKS key [{$kid}] does not declare a supported algorithm."),
        };
    }

    /**
     * @param  array<string, mixed>  $jwk
     */
    private function publicKeyPem(string $kid, array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;

        if ($kty === 'RSA' && ! isset($jwk['n'], $jwk['e'])) {
            throw new OidcException("The JWKS key [{$kid}] is missing modulus/exponent.");
        }

        if ($kty === 'EC' && ! isset($jwk['crv'], $jwk['x'], $jwk['y'])) {
            throw new OidcException("The JWKS key [{$kid}] is missing curve coordinates.");
        }

        if ($kty !== 'RSA' && $kty !== 'EC') {
            throw new OidcException("The JWKS key [{$kid}] has an unsupported key type.");
        }

        try {
            $key = $kty === 'RSA'
                ? RSA::loadFormat('JWK', (string) json_encode($jwk))
                : EC::loadFormat('JWK', (string) json_encode($jwk));

            return (string) $key->toString('PKCS8');
        } catch (Throwable $e) {
            throw new OidcException("The JWKS key [{$kid}] could not be parsed.", 0, $e);
        }
    }
}
