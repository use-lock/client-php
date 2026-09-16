<?php

declare(strict_types=1);

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\IdTokenValidator;
use Lock\Client\Auth\Tokens\JwksKeyResolver;

beforeEach(function () {
    $this->provider = new FakeProvider;
    $discovery = fakeDiscovery([[...$this->provider->rsaJwks('rsa'), ...$this->provider->ecJwks('ec')]]);
    $this->validator = new IdTokenValidator(new JwksKeyResolver($discovery), 'https://id.example.com/', 'client-123');
});

it('accepts a signed id token and returns its claims', function (string $kid, string $algorithm) {
    $claims = $this->validator->validate($this->provider->idToken(idTokenClaims(), $kid, $algorithm), 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and($claims['aud'])->toBe(['client-123']);
})->with([
    'RS256' => ['rsa', 'RS256'],
    'ES256' => ['ec', 'ES256'],
]);

it('rejects id tokens that fail a security check', function (Closure $token, string $message) {
    expect(fn () => $this->validator->validate($token($this->provider), 'the-nonce'))
        ->toThrow(OidcException::class, $message);
})->with([
    'wrong key' => [fn () => (new FakeProvider)->idToken(idTokenClaims(), 'rsa'), 'signature is invalid'],
    'alg downgrade' => [function () {
        $encoder = new JoseEncoder;
        $unsigned = $encoder->base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'rsa']))
            .'.'.$encoder->base64UrlEncode(json_encode(idTokenClaims()));

        return $unsigned.'.'.$encoder->base64UrlEncode(hash_hmac('sha256', $unsigned, 'attacker-secret', true));
    }, 'signature is invalid'],
    'wrong issuer' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['iss' => 'https://evil.example.com']), 'rsa'), 'issuer does not match'],
    'wrong audience' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['aud' => 'someone-else']), 'rsa'), 'audience does not include'],
    'azp mismatch' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['aud' => ['client-123', 'other'], 'azp' => 'other']), 'rsa'), 'azp does not match'],
    'nonce mismatch' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['nonce' => 'replayed']), 'rsa'), 'nonce does not match'],
    'expired' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['exp' => time() - 3600]), 'rsa'), 'has expired'],
]);
