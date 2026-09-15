<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Testing;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use phpseclib3\Crypt\RSA;

/**
 * An in-memory Lock realm for tests: it owns an RSA key, publishes it as a
 * JWKS document and signs RS256 tokens with it.
 */
class FakeProvider
{
    private readonly RSA\PrivateKey $key;

    public function __construct()
    {
        /** @var RSA\PrivateKey $key */
        $key = RSA::createKey(2048);
        $this->key = $key;
    }

    /**
     * The JWKS document as the realm serves it.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(string $kid): array
    {
        /** @var array<string, string> $jwk */
        $jwk = json_decode((string) $this->key->getPublicKey()->toString('JWK'), true)['keys'][0];

        return ['keys' => [[...$jwk, 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid]]];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function idToken(array $claims, string $kid): string
    {
        return $this->sign($claims, $kid);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function logoutToken(array $claims, string $kid): string
    {
        return $this->sign($claims, $kid, ['typ' => 'logout+jwt']);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $headers
     */
    private function sign(array $claims, string $kid, array $headers = []): string
    {
        $builder = new Builder(new JoseEncoder, ChainedFormatter::default())->withHeader('kid', $kid);

        foreach ($headers as $name => $value) {
            $builder = $builder->withHeader($name, $value);
        }

        foreach ($claims as $name => $value) {
            $builder = match ($name) {
                'iss' => $builder->issuedBy((string) $value),
                'sub' => $builder->relatedTo((string) $value),
                'aud' => $builder->permittedFor(...(array) $value),
                'exp' => $builder->expiresAt(new DateTimeImmutable()->setTimestamp((int) $value)),
                'nbf' => $builder->canOnlyBeUsedAfter(new DateTimeImmutable()->setTimestamp((int) $value)),
                'iat' => $builder->issuedAt(new DateTimeImmutable()->setTimestamp((int) $value)),
                'jti' => $builder->identifiedBy((string) $value),
                default => $builder->withClaim($name, $value),
            };
        }

        return $builder->getToken(new Sha256, InMemory::plainText((string) $this->key->toString('PKCS8')))->toString();
    }
}
