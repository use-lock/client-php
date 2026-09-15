<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Lock\Client\Auth\OidcException;

class IdTokenValidator extends TokenValidator
{
    /**
     * @return array<string, mixed>
     */
    public function validate(string $idToken, string $expectedNonce): array
    {
        $token = $this->verify($idToken);
        $claims = $token->claims();
        $now = time();

        $sub = $claims->get('sub');
        if (! is_string($sub) || $sub === '') {
            throw new OidcException('The id_token is missing a subject.');
        }

        $azp = $claims->get('azp');
        if ((count($claims->get('aud')) > 1 || $azp !== null) && $azp !== $this->clientId) {
            throw new OidcException('The id_token azp does not match this client.');
        }

        if ($claims->get('nonce') !== $expectedNonce) {
            throw new OidcException('The id_token nonce does not match.');
        }

        if ($now > $this->timestamp($token, 'exp') + $this->leeway) {
            throw new OidcException('The id_token has expired.');
        }

        $nbf = $this->timestamp($token, 'nbf', required: false);
        if ($nbf !== null && $now + $this->leeway < $nbf) {
            throw new OidcException('The id_token is not yet valid.');
        }

        if ($now + $this->leeway < $this->timestamp($token, 'iat')) {
            throw new OidcException('The id_token was issued in the future.');
        }

        return $claims->all();
    }

    protected function tokenName(): string
    {
        return 'id_token';
    }
}
