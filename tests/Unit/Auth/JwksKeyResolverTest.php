<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Lock\Client\Auth\ProviderException;
use Lock\Client\Auth\Tokens\JwksKeyResolver;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;

it('reports a JWKS the provider failed to serve as transient', function () {
    $resolver = new JwksKeyResolver(new DiscoveryApi(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(503, [], 'down')]))]), realm()));

    expect(fn () => $resolver->publicKey('any-kid'))->toThrow(
        fn (ProviderException $exception) => expect($exception->status)->toBe(503)->and($exception->isTransient())->toBeTrue(),
    );
});
