<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lock\Client\Admin\Api\RealmsApi;
use Lock\Client\Admin\ApiException;
use Lock\Client\Admin\Configuration;

it('sends bearer authentication and filters and decodes paginated realms', function () {
    $history = [];
    $handler = HandlerStack::create(new MockHandler([new Response(200, ['Content-Type' => 'application/json'],
        '{"data":[{"slug":"staging","name":"Staging"}],"links":[],"meta":{"current_page":2,"last_page":3,"total":3}}'
    )]));
    $handler->push(Middleware::history($history));
    $api = new RealmsApi(new Client(['handler' => $handler]), (new Configuration)->setHost('https://tenant.example/api')->setAccessToken('test-token'));

    $response = $api->listRealms(filterSlug: ['staging', 'production'], page: 2);

    $request = $history[0]['request'];
    expect($request->getMethod())->toBe('GET');
    expect((string) $request->getUri()->withQuery(''))->toBe('https://tenant.example/api/v1/realms');
    expect($request->getHeaderLine('Authorization'))->toBe('Bearer test-token');
    parse_str($request->getUri()->getQuery(), $query);
    expect($query)->toBe(['filter' => ['slug' => 'staging,production'], 'page' => '2']);
    expect($response->getData()[0]->getSlug())->toBe('staging');
    expect($response->getMeta()->getCurrentPage())->toBe(2);
});

it('retains status and decoded error bodies', function (int $status, string $body) {
    $api = new RealmsApi(new Client(['handler' => HandlerStack::create(new MockHandler([
        new Response($status, ['Content-Type' => 'application/json'], $body),
    ]))]));

    try {
        $api->getRealm('missing');
        test()->fail('Expected an API error.');
    } catch (ApiException $exception) {
        expect($exception->getCode())->toBe($status);
        expect($exception->getResponseBody())->toBe($body);
        expect($exception->getResponseObject())->not->toBeNull();
    }
})->with([
    [401, '{"error":"invalid_token","error_description":"Denied"}'],
    [403, '{"message":"Forbidden"}'],
    [404, '{"message":"Not found"}'],
]);

it('accepts an empty successful deletion response', function () {
    $api = new RealmsApi(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(204)]))]));

    expect($api->deleteRealm('staging'))->toBeNull();
});
