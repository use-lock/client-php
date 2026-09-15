# use-lock/client-php

A framework-independent PHP client for [Lock](https://github.com/use-lock/lock). It has two parts:

- A handwritten auth layer for signing users in, obtaining tokens and validating the tokens a realm issues.
- Clients for the Admin, Management and Auth APIs, generated from Lock's OpenAPI specs.

It is built for Lock only and does not work with other OpenID Connect providers.

Requires PHP 8.5.

## Installation

```bash
composer require use-lock/client-php
```

## Configure a Realm

`Lock\Client\Realm` describes one client registered in one realm. The realm URL is the host of every protocol endpoint and the issuer of every token the realm mints.

```php
use Lock\Client\Realm;

$realm = new Realm(
    url: 'https://id.example.com',
    clientId: 'my-app',
    clientSecret: 'secret',                           // omit for public clients
    redirectUri: 'https://app.example.com/callback',  // only for the login flow
    basicAuth: false,                                  // true for client_secret_basic clients
    cache: $cache,                                     // any PSR-16 cache, recommended
);
```

The cache stores the realm's signing keys and client credentials tokens. Without a cache, each new `Realm` fetches the keys again.

## Sign Users In

The login flow uses an authorization code with PKCE. Store the `AuthorizationRequest` from `begin()`, for example in the session, and pass it to `complete()` in the callback.

```php
$request = $realm->authorization()->begin(['openid', 'profile', 'email']);
// Store $request, then redirect the browser to $request->url.

// In the callback:
$tokens = $realm->authorization()->complete($request, $_GET);

$tokens->accessToken;
$tokens->refreshToken;
$tokens->claims['sub'];
```

`complete()` checks state, exchanges the code and validates the ID token. Every failure throws `Lock\Client\Auth\OidcException`.

To log out at the provider, redirect to the logout URL:

```php
$url = $realm->authorization()->logoutUrl($tokens->idToken, 'https://app.example.com');
```

## Obtain Tokens

```php
$tokens = $realm->tokens();

$tokens->refresh($refreshToken);
$tokens->exchange($accessToken, audience: 'https://api.example.com');
$tokens->clientCredentials(resource: 'https://id.example.com/api');
```

Each call returns a `TokenSet` with `expiresIn()`, `isExpired()` and `hasScope()`. The cache holds client credentials tokens until 30 seconds before they expire.

## Validate Tokens

```php
$claims = $realm->idTokens()->validate($idToken, $expectedNonce);
```

To handle back-channel logout, validate the logout token and reject a `jti` that has already been used:

```php
use Lock\Client\Auth\Tokens\LogoutTokenReplay;

['sid' => $sid, 'jti' => $jti, 'exp' => $exp] = $realm->logoutTokens()->validate($logoutToken);

if ($jti !== null && ! (new LogoutTokenReplay($cache))->consume($jti, $exp)) {
    // Replayed logout token.
}
```

## Admin and Management APIs

The generated clients live in `Lock\Client\OpenApi\{Admin,Management,Auth}`. The Admin and Management APIs are served under `/api` of the master realm. Authenticate with a client credentials token whose `resource` is `{issuer}/admin-api` for the Admin API or `{issuer}/api` for the Management API.

```php
use Lock\Client\OpenApi\Management\Api\ClientsApi;
use Lock\Client\OpenApi\Management\Configuration;

$token = $realm->tokens()->clientCredentials(resource: 'https://id.example.com/api');

$clients = new ClientsApi(config: (new Configuration)
    ->setHost('https://id.example.com/api')
    ->setAccessToken($token->accessToken));

$clients->listClients('my-realm');
```

## Testing

`Lock\Client\Auth\Testing\FakeProvider` generates an RSA key and signs ID and logout tokens for your tests. `jwks($kid)` returns the matching key set.

## Development

```bash
composer check            # Pint, PHPStan and Pest
composer sync-openapi     # download Lock's specs from GitHub and regenerate the clients
composer check:generated  # confirm src/OpenApi matches the specs
```

`composer sync-openapi` reads the specs from `use-lock/lock` at `main`. Set `LOCK_REF` to use another branch, tag or commit. Never edit `src/OpenApi` by hand.
