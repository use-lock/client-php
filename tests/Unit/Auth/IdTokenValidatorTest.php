<?php

declare(strict_types=1);

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\IdTokenValidator;

beforeEach(function () {
    $this->provider = new FakeProvider;
    $this->validator = new IdTokenValidator(keyResolver([$this->provider->jwks('kid')]), 'https://id.example.com', 'client-123');
});

it('accepts a signed id token and returns its claims', function () {
    $claims = $this->validator->validate($this->provider->idToken(idTokenClaims(), 'kid'), 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and($claims['aud'])->toBe(['client-123']);
});

it('rejects id tokens that fail a security check', function (Closure $token, string $message) {
    expect(fn () => $this->validator->validate($token($this->provider), 'the-nonce'))
        ->toThrow(OidcException::class, $message);
})->with([
    'wrong key' => [fn () => new FakeProvider()->idToken(idTokenClaims(), 'kid'), 'signature is invalid'],
    'alg downgrade' => [function () {
        $encoder = new JoseEncoder;
        $unsigned = $encoder->base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'kid']))
            .'.'.$encoder->base64UrlEncode(json_encode(idTokenClaims()));

        return $unsigned.'.'.$encoder->base64UrlEncode(hash_hmac('sha256', $unsigned, 'attacker-secret', true));
    }, 'signature is invalid'],
    'wrong issuer' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['iss' => 'https://evil.example.com']), 'kid'), 'issuer does not match'],
    'wrong audience' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['aud' => 'someone-else']), 'kid'), 'audience does not include'],
    'azp mismatch' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['aud' => ['client-123', 'other'], 'azp' => 'other']), 'kid'), 'azp does not match'],
    'nonce mismatch' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['nonce' => 'replayed']), 'kid'), 'nonce does not match'],
    'expired' => [fn (FakeProvider $p) => $p->idToken(idTokenClaims(['exp' => time() - 3600]), 'kid'), 'has expired'],
]);

it('refetches the JWKS once for an unknown kid', function () {
    $history = [];
    $old = new FakeProvider;
    $new = new FakeProvider;
    $validator = new IdTokenValidator(keyResolver([$old->jwks('old'), $new->jwks('new')], $history), 'https://id.example.com', 'client-123');

    $validator->validate($old->idToken(idTokenClaims(), 'old'), 'the-nonce');
    $validator->validate($old->idToken(idTokenClaims(), 'old'), 'the-nonce');
    $claims = $validator->validate($new->idToken(idTokenClaims(), 'new'), 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and(array_map(fn (array $entry): string => (string) $entry['request']->getUri(), $history))
        ->toBe(array_fill(0, 2, 'https://id.example.com/.well-known/jwks.json'));
});
