<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use DateTimeInterface;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Client\Auth\OidcException;
use Throwable;

/**
 * Shared machinery for validating provider-issued JWTs: parse, verify the
 * signature against the provider's JWKS with an allow-listed algorithm, and
 * assert the claims every token type has in common.
 */
abstract class TokenValidator
{
    private readonly Parser $parser;

    private readonly Validator $signatureValidator;

    public function __construct(
        private readonly JwksKeyResolver $keys,
        protected readonly string $issuer,
        protected readonly string $clientId,
        protected readonly int $leeway = 60,
    ) {
        $this->parser = new Parser(new JoseEncoder);
        $this->signatureValidator = new Validator;
    }

    /**
     * The token name used in exception messages (e.g. "id_token").
     */
    abstract protected function tokenName(): string;

    protected function parseAndVerifySignature(string $jwt): UnencryptedToken
    {
        $name = $this->tokenName();

        try {
            $token = $this->parser->parse($jwt);
        } catch (Throwable $e) {
            throw new OidcException("The {$name} could not be parsed.", 0, $e);
        }

        if (! $token instanceof UnencryptedToken) {
            throw new OidcException("The {$name} is not a signed JWT.");
        }

        $this->assertHeaders($token);

        $kid = $token->headers()->get('kid');

        if (! is_string($kid)) {
            throw new OidcException("The {$name} has no kid header.");
        }

        [$pem, $algorithm] = $this->keys->signingKey($kid);
        $constraint = new SignedWith($this->signer($algorithm), InMemory::plainText($pem));

        // SignedWith also rejects tokens whose alg header differs from the
        // JWK's algorithm, so a downgraded header (none, HS256, ...) can never
        // reach signature verification with an asymmetric public key.
        if (! $this->signatureValidator->validate($token, $constraint)) {
            throw new OidcException("The {$name} signature is invalid.");
        }

        return $token;
    }

    /**
     * PS256 is intentionally absent: lcobucci/jwt 5 ships no RSASSA-PSS signer.
     */
    private function signer(string $algorithm): Signer
    {
        return match ($algorithm) {
            'RS256' => new RsaSha256,
            'ES256' => new EcdsaSha256,
            default => throw new OidcException("The {$this->tokenName()} signature algorithm [{$algorithm}] is not supported."),
        };
    }

    /**
     * Token-specific header assertions, run before any JWKS lookup.
     */
    protected function assertHeaders(UnencryptedToken $token): void {}

    protected function assertIssuer(UnencryptedToken $token): void
    {
        if (rtrim((string) $token->claims()->get('iss'), '/') !== rtrim($this->issuer, '/')) {
            throw new OidcException("The {$this->tokenName()} issuer does not match.");
        }
    }

    /**
     * @return array<int, mixed>
     */
    protected function assertAudience(UnencryptedToken $token): array
    {
        $audience = (array) $token->claims()->get('aud', []);

        if (! in_array($this->clientId, $audience, true)) {
            throw new OidcException("The {$this->tokenName()} audience does not include this client.");
        }

        return $audience;
    }

    protected function timestamp(mixed $value, string $claim, bool $required = false): ?int
    {
        if ($value instanceof DateTimeInterface) {
            return $value->getTimestamp();
        }

        if (is_numeric($value)) {
            return (int) $value;
        }

        if ($required) {
            throw new OidcException("The {$this->tokenName()} is missing or invalid {$claim} timestamp.");
        }

        if ($value !== null) {
            throw new OidcException("The {$this->tokenName()} {$claim} timestamp is invalid.");
        }

        return null;
    }
}
