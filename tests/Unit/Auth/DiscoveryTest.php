<?php

declare(strict_types=1);

use Lock\Client\Auth\Discovery;
use Lock\Client\Auth\OidcException;
use Lock\Client\Auth\Testing\FakeProvider;
use Lock\Client\Auth\Tokens\IdTokenValidator;
use Lock\Client\Auth\Tokens\JwksKeyResolver;

it('rejects a discovery document for another issuer', function () {
    $discovery = new Discovery('https://id.example.com', arrayCache(), jsonClient([discoveryDocument('https://evil.example.com')]));

    expect(fn () => $discovery->metadata())->toThrow(OidcException::class, 'issuer does not match');
});

it('serves metadata and keys from the cache on later calls', function () {
    $history = [];
    $cache = arrayCache();
    $http = jsonClient([discoveryDocument(), ['keys' => [['kid' => 'abc', 'kty' => 'RSA']]]], $history);

    (new Discovery('https://id.example.com/', $cache, $http))->jwks();
    $discovery = new Discovery('https://id.example.com/', $cache, $http);

    expect($discovery->metadata()->getTokenEndpoint())->toBe('https://id.example.com/oauth/token')
        ->and($discovery->jwks()[0]['kid'])->toBe('abc')
        ->and($history)->toHaveCount(2);
});

it('refetches the JWKS exactly once for an unknown kid', function () {
    $history = [];
    $old = new FakeProvider;
    $new = new FakeProvider;
    $discovery = fakeDiscovery([$old->rsaJwks('old'), $new->rsaJwks('new')], $history);
    $validator = new IdTokenValidator(new JwksKeyResolver($discovery), 'https://id.example.com', 'client-123');

    $validator->validate($old->idToken(idTokenClaims(), 'old'), 'the-nonce');
    $claims = $validator->validate($new->idToken(idTokenClaims(), 'new'), 'the-nonce');

    expect($claims['sub'])->toBe('42')
        ->and(array_map(fn (array $entry): string => (string) $entry['request']->getUri(), $history))->toBe([
            'https://id.example.com/.well-known/openid-configuration',
            'https://id.example.com/.well-known/jwks.json',
            'https://id.example.com/.well-known/jwks.json',
        ]);
});
