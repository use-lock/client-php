<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Lcobucci\JWT\UnencryptedToken;
use Lock\Client\Auth\OidcException;

class LogoutTokenValidator extends TokenValidator
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /**
     * @return array{sid: string, sub: string, jti: string|null, exp: int}
     */
    public function validate(string $logoutToken): array
    {
        $token = $this->verify($logoutToken);
        $claims = $token->claims();
        $now = time();

        if ($claims->has('nonce')) {
            throw new OidcException('A logout token must not contain a nonce.');
        }

        if (! array_key_exists(self::EVENT, (array) $claims->get('events'))) {
            throw new OidcException('The logout token is missing the back-channel logout event.');
        }

        $exp = $this->timestamp($token, 'exp');
        if ($now > $exp + $this->leeway) {
            throw new OidcException('The logout token has expired.');
        }

        if ($now - $this->timestamp($token, 'iat') > $this->leeway + 300) {
            throw new OidcException('The logout token was issued too long ago.');
        }

        $sid = $claims->get('sid');
        if (! is_string($sid) || $sid === '') {
            throw new OidcException('The logout token is missing a sid.');
        }

        $sub = $claims->get('sub');
        $jti = $claims->get('jti');

        return [
            'sid' => $sid,
            'sub' => is_string($sub) ? $sub : '',
            'jti' => is_string($jti) && $jti !== '' ? $jti : null,
            'exp' => $exp,
        ];
    }

    protected function tokenName(): string
    {
        return 'logout token';
    }

    protected function assertHeaders(UnencryptedToken $token): void
    {
        if ($token->headers()->get('typ') !== 'logout+jwt') {
            throw new OidcException('The logout token has an invalid typ header.');
        }
    }
}
