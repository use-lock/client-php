<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$outputDirectory = $argv[1] ?? $root.'/.cache';
$spec = json_decode(file_get_contents($root.'/openapi/lock.json'), true, flags: JSON_THROW_ON_ERROR);

$operations = json_decode(file_get_contents($root.'/openapi/operations.json'), true, flags: JSON_THROW_ON_ERROR);

foreach (['Management', 'Oidc'] as $group) {
    $document = $spec;
    $document['paths'] = [];
    $formModels = [];
    $tokenVariants = [];
    $document['servers'] = [['url' => $group === 'Management' ? 'https://lock.example/api' : 'https://lock.example']];

    foreach ($spec['paths'] as $path => $pathOperations) {
        foreach ($pathOperations as $method => $operation) {
            $isManagement = array_intersect($operation['tags'] ?? [], ['Admin API', 'Management API']) !== [];

            if ($isManagement !== ($group === 'Management')) {
                continue;
            }

            // Per-operation example servers override Configuration::setHost() in the PHP generator.
            unset($operation['servers'], $operation['x-internal']);
            $id = $operation['operationId'];
            if (! array_key_exists($id, $operations)) {
                throw new RuntimeException('Missing public API name for '.$id);
            }
            if ($operations[$id] === null) {
                continue;
            }
            [$tag, $name] = $operations[$id];
            $operation['tags'] = [$tag];
            $operation['operationId'] = $name;
            $formSchema = $operation['requestBody']['content']['application/x-www-form-urlencoded']['schema']['$ref'] ?? null;
            if ($formSchema !== null) {
                $formModels[] = basename($formSchema);
            }
            if ($name === 'issueToken') {
                $operation['x-php-token-request'] = true;
                $requestSchema = $spec['components']['schemas'][basename($operation['requestBody']['content']['application/x-www-form-urlencoded']['schema']['$ref'])];
                $tokenVariants = array_map(fn (array $variant): string => basename($variant['$ref']), $requestSchema['oneOf']);
                $operation['x-php-token-types'] = implode('|', array_map(
                    fn (array $variant): string => '\\Lock\\Client\\'.$group.'\\Model\\'.basename($variant['$ref']),
                    $requestSchema['oneOf'],
                ));
            }
            foreach ($operation['parameters'] ?? [] as $index => $parameter) {
                if (($parameter['name'] ?? null) === 'resource' && isset($parameter['schema']['oneOf'])) {
                    $operation['parameters'][$index]['x-php-resource'] = true;
                }
            }
            foreach ($operation['responses'] as $status => &$response) {
                if (! isset($response['content']['application/json']['schema']['properties'])) {
                    continue;
                }
                $schema = &$response['content']['application/json']['schema'];
                $properties = $schema['properties'];
                if (isset($properties['data']['items']['$ref'])) {
                    $model = basename($properties['data']['items']['$ref']);
                    $schema['title'] = preg_replace('/Data$/', '', $model).'Collection';
                    $schema['properties']['links']['items']['title'] = 'PaginationLink';
                    $schema['properties']['meta']['title'] = 'PaginationMeta';
                } elseif (isset($properties['data']['$ref'])) {
                    $schema['title'] = preg_replace('/Data$/', '', basename($properties['data']['$ref'])).'Response';
                } elseif (isset($properties['errors'])) {
                    $schema['title'] = 'ValidationError';
                } elseif (isset($properties['error'])) {
                    $schema['title'] = (string) $status === '403' ? 'AuthorizationError' : 'AuthenticationError';
                } elseif (isset($properties['message'])) {
                    $schema['title'] = 'ErrorResponse';
                }
                unset($schema);
            }
            unset($response);
            $document['paths'][$path][$method] = $operation;
        }
    }

    $schemas = [];
    $responses = [];
    $collectReferences = function (mixed $value) use (&$collectReferences, &$schemas, &$responses, $spec): void {
        if (! is_array($value)) {
            return;
        }

        foreach ($value as $key => $child) {
            if ($key === '$ref' && str_starts_with($child, '#/components/schemas/')) {
                $name = substr($child, strlen('#/components/schemas/'));

                if (! array_key_exists($name, $schemas)) {
                    $schemas[$name] = $spec['components']['schemas'][$name];
                    $collectReferences($schemas[$name]);
                }
            } elseif ($key === '$ref' && str_starts_with($child, '#/components/responses/')) {
                $name = substr($child, strlen('#/components/responses/'));
                if (! array_key_exists($name, $responses)) {
                    $responses[$name] = $spec['components']['responses'][$name];
                    $collectReferences($responses[$name]);
                }
            } else {
                $collectReferences($child);
            }
        }
    };
    $collectReferences($document['paths']);
    $document['components']['schemas'] = $schemas;
    $document['components']['responses'] = $responses;

    $renames = [
        'OAuthClientRegistration' => 'ClientRegistrationRequest',
        'OAuthRegisteredClient' => 'RegisteredClient',
        'OAuthTokenResponse' => 'TokenResponse',
        'OAuthIntrospection' => 'TokenIntrospection',
        'OAuthProtectedResource' => 'ProtectedResourceMetadata',
        'OidcProviderMetadata' => 'ProviderMetadata',
        'OidcJwks' => 'JsonWebKeySet',
        'OidcUserinfo' => 'UserInfo',
    ];
    if (isset($document['components']['schemas']['OidcJwks'])) {
        $document['components']['schemas']['OidcJwks']['properties']['keys']['items']['title'] = 'JsonWebKey';
    }
    $renameReferences = function (array $value) use (&$renameReferences, $renames): array {
        foreach ($value as $key => $child) {
            if ($key === '$ref' && str_starts_with($child, '#/components/schemas/')) {
                $name = basename($child);
                $value[$key] = '#/components/schemas/'.($renames[$name] ?? $name);
            } elseif (is_array($child)) {
                $value[$key] = $renameReferences($child);
            }
        }

        return $value;
    };
    $document = $renameReferences($document);
    foreach ($renames as $original => $renamed) {
        if (isset($document['components']['schemas'][$original])) {
            $document['components']['schemas'][$renamed] = $document['components']['schemas'][$original];
            unset($document['components']['schemas'][$original]);
        }
    }

    $normalizeSchemas = function (array $value) use (&$normalizeSchemas): array {
        // PHP's generator otherwise emits an empty class for string/list resource indicators.
        if (isset($value['oneOf']) && array_column($value['oneOf'], 'type') === ['string', 'array']) {
            unset($value['oneOf']);
            $value['type'] = 'string';
            $value['x-php-resource'] = true;
        }
        if (($value['additionalProperties'] ?? false) === true) {
            $value['x-php-open-object'] = true;
        }

        foreach ($value as $key => $child) {
            if (is_array($child)) {
                $value[$key] = $normalizeSchemas($child);
            }
        }

        return $value;
    };
    foreach ($document['components']['responses'] as $responseName => &$response) {
        $response['content']['application/json']['schema']['title'] = match ($responseName) {
            'ValidationException' => 'ValidationError',
            'ModelNotFoundException' => 'NotFoundError',
            default => $responseName,
        };
    }
    unset($response);
    if ($document['components']['responses'] === []) {
        unset($document['components']['responses']);
    }
    foreach ($document['components']['schemas'] as $schemaName => &$schema) {
        foreach (in_array($schemaName, $tokenVariants, true) ? ($schema['required'] ?? []) : [] as $property) {
            if (count($schema['properties'][$property]['enum'] ?? []) === 1) {
                $schema['properties'][$property]['default'] ??= $schema['properties'][$property]['enum'][0];
            }
        }
        if (isset($schema['anyOf']) && array_all($schema['anyOf'], fn (array $variant): bool => array_keys($variant) === ['required'])) {
            $schema['x-php-required-alternatives'] = var_export(array_column($schema['anyOf'], 'required'), true);
        }
    }
    unset($schema);
    $document = $normalizeSchemas($document);

    file_put_contents($outputDirectory.'/'.$group.'.ignore', implode("\n", array_map(fn (string $name): string => 'src/Model/'.($renames[$name] ?? $name).'.php', array_unique($formModels)))."\n");

    file_put_contents($outputDirectory.'/'.$group.'.json', json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
}
