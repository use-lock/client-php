<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Testing;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Token\Builder;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

/**
 * An in-memory OpenID provider for tests: it owns an RSA and an EC P-256
 * signing key, publishes them as JWKS entries and signs tokens with them.
 */
class FakeProvider
{
    private readonly RSA\PrivateKey $rsaPrivateKey;

    private ?EC\PrivateKey $ecPrivateKey = null;

    public function __construct()
    {
        /** @var RSA\PrivateKey $key */
        $key = RSA::createKey(2048);
        $this->rsaPrivateKey = $key;
    }

    /**
     * @return array<int, array<string, string>>
     */
    public function rsaJwks(string $kid): array
    {
        /** @var array<string, string> $jwk */
        $jwk = json_decode((string) $this->rsaPrivateKey->getPublicKey()->toString('JWK'), true)['keys'][0];

        return [[...$jwk, 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid]];
    }

    /**
     * @return array<int, array<string, string>>
     */
    public function ecJwks(string $kid): array
    {
        /** @var array<string, string> $jwk */
        $jwk = json_decode((string) $this->ecPrivateKey()->getPublicKey()->toString('JWK'), true)['keys'][0];

        return [[...$jwk, 'use' => 'sig', 'alg' => 'ES256', 'kid' => $kid]];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function idToken(array $claims, string $kid, string $algorithm = 'RS256'): string
    {
        return $this->build($claims, $kid, $algorithm);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function logoutToken(array $claims, string $kid, string $algorithm = 'RS256'): string
    {
        return $this->build($claims, $kid, $algorithm, ['typ' => 'logout+jwt']);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @param  array<string, string>  $headers
     */
    private function build(array $claims, string $kid, string $algorithm, array $headers = []): string
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
                'exp' => $builder->expiresAt($this->toDateTime($value)),
                'nbf' => $builder->canOnlyBeUsedAfter($this->toDateTime($value)),
                'iat' => $builder->issuedAt($this->toDateTime($value)),
                'jti' => $builder->identifiedBy((string) $value),
                default => $builder->withClaim($name, $value),
            };
        }

        [$signer, $pem] = $this->signerFor($algorithm);

        return $builder->getToken($signer, InMemory::plainText($pem))->toString();
    }

    /**
     * @return array{0: Signer, 1: string}
     */
    private function signerFor(string $algorithm): array
    {
        return match ($algorithm) {
            'RS256' => [new RsaSha256, (string) $this->rsaPrivateKey->toString('PKCS8')],
            'ES256' => [new EcdsaSha256, (string) $this->ecPrivateKey()->toString('PKCS8')],
            default => throw new InvalidArgumentException("The fake provider cannot sign with [{$algorithm}]."),
        };
    }

    private function ecPrivateKey(): EC\PrivateKey
    {
        /** @var EC\PrivateKey */
        return $this->ecPrivateKey ??= EC::createKey('secp256r1');
    }

    private function toDateTime(mixed $value): DateTimeImmutable
    {
        return new DateTimeImmutable()->setTimestamp((int) $value);
    }
}
