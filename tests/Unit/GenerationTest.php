<?php

declare(strict_types=1);

it('exposes the named client operations without consent or async endpoints', function () {
    $spec = json_decode(file_get_contents(__DIR__.'/../../openapi/lock.json'), true, flags: JSON_THROW_ON_ERROR);

    $names = json_decode(file_get_contents(__DIR__.'/../../openapi/operations.json'), true, flags: JSON_THROW_ON_ERROR);
    $exposed = 0;

    foreach ($spec['paths'] as $operations) {
        foreach ($operations as $operation) {
            $tag = $operation['tags'][0];
            $group = in_array($tag, ['Admin API', 'Management API'], true) ? 'Management' : 'Oidc';
            $id = $operation['operationId'];
            expect(array_key_exists($id, $names))->toBeTrue();
            if (in_array($id, ['oidc.approve.post', 'oidc.deny.delete'], true)) {
                expect($names[$id])->toBeNull();

                continue;
            }
            [$tag, $method] = $names[$id];
            $exposed++;
            $api = 'Lock\\Client\\'.$group.'\\Api\\'.str_replace(' API', '', $tag).'Api';

            expect(method_exists($api, $method))->toBeTrue();
            expect(method_exists($api, $method.'Async'))->toBeFalse();
            expect(method_exists($api, $method.'AsyncWithHttpInfo'))->toBeFalse();
        }
    }
    expect($exposed)->toBe(42);
});
