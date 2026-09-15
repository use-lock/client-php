<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use DateTimeInterface;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Lock\Client\Auth\OidcException;
use Throwable;

/**
 * Parses a Lock-issued JWT, verifies its RS256 signature against the realm
 * JWKS and checks the issuer and audience every token type shares.
 */
abstract class TokenValidator
{
    public function __construct(
        private readonly JwksKeyResolver $keys,
        private readonly string $issuer,
        protected readonly string $clientId,
        protected readonly int $leeway = 60,
    ) {}

    /**
     * The token name used in exception messages (e.g. "id_token").
     */
    abstract protected function tokenName(): string;

    /**
     * Token-specific header assertions, run before any JWKS lookup.
     */
    protected function assertHeaders(UnencryptedToken $token): void {}

    protected function verify(string $jwt): UnencryptedToken
    {
        $name = $this->tokenName();

        try {
            $token = new Parser(new JoseEncoder)->parse($jwt);
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

        // SignedWith also rejects any alg header other than RS256 (none, HS256, ...).
        if (! new Validator()->validate($token, new SignedWith(new Sha256, InMemory::plainText($this->keys->publicKey($kid))))) {
            throw new OidcException("The {$name} signature is invalid.");
        }

        if (rtrim((string) $token->claims()->get('iss'), '/') !== rtrim($this->issuer, '/')) {
            throw new OidcException("The {$name} issuer does not match.");
        }

        if (! in_array($this->clientId, (array) $token->claims()->get('aud', []), true)) {
            throw new OidcException("The {$name} audience does not include this client.");
        }

        return $token;
    }

    /**
     * The parser has already turned exp, nbf and iat into dates or rejected the token.
     */
    protected function timestamp(UnencryptedToken $token, string $claim, bool $required = true): ?int
    {
        $value = $token->claims()->get($claim);

        if (! $value instanceof DateTimeInterface && $required) {
            throw new OidcException("The {$this->tokenName()} is missing the {$claim} timestamp.");
        }

        return $value?->getTimestamp();
    }
}
