<?php

declare(strict_types=1);

use Lock\Client\Oidc\Api\AuthorizationApi;
use Lock\Client\Oidc\Configuration;

it('builds authorization URLs with scalar and multiple resource indicators', function (string|array $resource) {
    $api = new AuthorizationApi(config: (new Configuration)->setHost('https://realm.example'));

    $request = $api->authorizeRequest(
        clientId: 'app',
        responseType: 'code',
        codeChallenge: str_repeat('a', 43),
        codeChallengeMethod: 'S256',
        redirectUri: 'https://app.example/callback',
        state: 'state+&=',
        resource: $resource,
    );

    expect((string) $request->getUri()->withQuery(''))->toBe('https://realm.example/oauth/authorize');
    parse_str($request->getUri()->getQuery(), $query);
    expect($query)->toBe([
        'client_id' => 'app',
        'response_type' => 'code',
        'redirect_uri' => 'https://app.example/callback',
        'state' => 'state+&=',
        'resource' => $resource,
        'code_challenge' => str_repeat('a', 43),
        'code_challenge_method' => 'S256',
    ]);
})->with([
    'single resource' => ['https://api.example'],
    'multiple resources' => [['https://api.example', 'https://other.example']],
]);
