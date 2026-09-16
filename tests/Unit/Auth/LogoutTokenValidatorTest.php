<?php

declare(strict_types=1);

use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\JwksKeyResolver;
use Lock\Client\Auth\Tokens\LogoutTokenValidator;

beforeEach(function () {
    $this->provider = new FakeProvider;
    $discovery = fakeDiscovery([$this->provider->rsaJwks('rsa')]);
    $this->validator = new LogoutTokenValidator(new JwksKeyResolver($discovery), 'https://id.example.com', 'client-123');
});

it('accepts a logout token and returns its session claims', function () {
    $claims = logoutTokenClaims();

    expect($this->validator->validate($this->provider->logoutToken($claims, 'rsa')))
        ->toBe(['sid' => 'sess-abc', 'sub' => '42', 'jti' => 'jti-1', 'exp' => $claims['exp']]);
});

it('rejects logout tokens that fail a security check', function (Closure $token, string $message) {
    expect(fn () => $this->validator->validate($token($this->provider)))
        ->toThrow(OidcException::class, $message);
})->with([
    'wrong typ' => [fn (FakeProvider $p) => $p->idToken(logoutTokenClaims(), 'rsa'), 'invalid typ header'],
    'nonce present' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['nonce' => 'x']), 'rsa'), 'must not contain a nonce'],
    'missing events' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['events' => ['other' => (object) []]]), 'rsa'), 'back-channel logout event'],
    'missing sid' => [fn (FakeProvider $p) => $p->logoutToken(array_diff_key(logoutTokenClaims(), ['sid' => true]), 'rsa'), 'missing a sid'],
]);
