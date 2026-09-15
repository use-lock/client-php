<?php

declare(strict_types=1);

use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\LogoutTokenReplay;
use Lock\Client\Auth\Tokens\LogoutTokenValidator;

beforeEach(function () {
    $this->provider = new FakeProvider;
    $this->validator = new LogoutTokenValidator(keyResolver([$this->provider->jwks('kid')]), 'https://id.example.com', 'client-123');
});

it('accepts a logout token and returns its session claims', function () {
    $claims = logoutTokenClaims();

    expect($this->validator->validate($this->provider->logoutToken($claims, 'kid')))
        ->toBe(['sid' => 'sess-abc', 'sub' => '42', 'jti' => 'jti-1', 'exp' => $claims['exp']]);
});

it('rejects logout tokens that fail a security check', function (Closure $token, string $message) {
    expect(fn () => $this->validator->validate($token($this->provider)))
        ->toThrow(OidcException::class, $message);
})->with([
    'wrong typ' => [fn (FakeProvider $p) => $p->idToken(logoutTokenClaims(), 'kid'), 'invalid typ header'],
    'wrong audience' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['aud' => 'other']), 'kid'), 'audience does not include'],
    'nonce present' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['nonce' => 'x']), 'kid'), 'must not contain a nonce'],
    'missing events' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['events' => ['other' => (object) []]]), 'kid'), 'back-channel logout event'],
    'missing sid' => [fn (FakeProvider $p) => $p->logoutToken(logoutTokenClaims(['sid' => '']), 'kid'), 'missing a sid'],
]);

it('consumes a logout token jti only once', function () {
    $replay = new LogoutTokenReplay(arrayCache());

    expect($replay->consume('jti-1', time() + 120))->toBeTrue()
        ->and($replay->consume('jti-1', time() + 120))->toBeFalse()
        ->and($replay->consume('jti-2', time() + 120))->toBeTrue();
});
