<?php

declare(strict_types=1);

use Lock\Client\Management\Api\ClientsApi;
use Lock\Client\Management\Configuration;
use Lock\Client\Management\Model\UpdateClientData;

it('preserves omitted, null and zero values in PATCH bodies', function (array $data, string $expected) {
    $api = new ClientsApi(config: (new Configuration)->setHost('https://tenant.example/api'));

    $request = $api->patchClientRequest('staging', 'client/123', new UpdateClientData($data));

    expect($request->getMethod())->toBe('PATCH');
    expect($request->getUri()->getPath())->toBe('/api/v1/realms/staging/clients/client%2F123');
    expect(json_decode((string) $request->getBody(), flags: JSON_THROW_ON_ERROR))
        ->toEqual(json_decode($expected, flags: JSON_THROW_ON_ERROR));
})->with([
    'omitted' => [[], '{}'],
    'null' => [['backchannelLogoutUri' => null], '{"backchannel_logout_uri":null}'],
    'value' => [['backchannelLogoutUri' => 'https://app.example/logout'], '{"backchannel_logout_uri":"https://app.example/logout"}'],
    'zero values' => [['consentRequired' => false, 'redirectUris' => []], '{"consent_required":false,"redirect_uris":[]}'],
]);
