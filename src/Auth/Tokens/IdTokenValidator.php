<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Lcobucci\JWT\UnencryptedToken;
use Lock\Client\Auth\OidcException;

class IdTokenValidator extends TokenValidator
{
    /**
     * @return array<string, mixed>
     */
    public function validate(string $idToken, string $expectedNonce): array
    {
        $token = $this->parseAndVerifySignature($idToken);

        $this->assertClaims($token, $expectedNonce);

        return $token->claims()->all();
    }

    protected function tokenName(): string
    {
        return 'id_token';
    }

    private function assertClaims(UnencryptedToken $token, string $expectedNonce): void
    {
        $claims = $token->claims();
        $now = time();

        $this->assertIssuer($token);

        $sub = $claims->get('sub');
        if (! is_string($sub) || $sub === '') {
            throw new OidcException('The id_token is missing a subject.');
        }

        $audience = $this->assertAudience($token);

        $azp = $claims->get('azp');
        if (count($audience) > 1) {
            if (! is_string($azp) || $azp !== $this->clientId) {
                throw new OidcException('The id_token azp does not match this client.');
            }
        } elseif (is_string($azp) && $azp !== $this->clientId) {
            throw new OidcException('The id_token azp does not match this client.');
        }

        if ($claims->get('nonce') !== $expectedNonce) {
            throw new OidcException('The id_token nonce does not match.');
        }

        $exp = $this->timestamp($claims->get('exp'), 'exp', required: true);
        if ($now > $exp + $this->leeway) {
            throw new OidcException('The id_token has expired.');
        }

        $nbf = $this->timestamp($claims->get('nbf'), 'nbf');
        if ($nbf !== null && $now + $this->leeway < $nbf) {
            throw new OidcException('The id_token is not yet valid.');
        }

        $iat = $this->timestamp($claims->get('iat'), 'iat', required: true);
        if ($now + $this->leeway < $iat) {
            throw new OidcException('The id_token was issued in the future.');
        }
    }
}
