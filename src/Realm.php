<?php

declare(strict_types=1);

namespace Lock\Client;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Lock\Client\Auth\Authorization;
use Lock\Client\Auth\Tokens\IdTokenValidator;
use Lock\Client\Auth\Tokens\JwksKeyResolver;
use Lock\Client\Auth\Tokens\LogoutTokenValidator;
use Lock\Client\Auth\Tokens\TokenClient;
use Lock\Client\OpenApi\Auth\Api\DiscoveryApi;
use Lock\Client\OpenApi\Auth\Configuration;
use LogicException;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;

/**
 * A client registered in one Lock realm. The realm URL is both the host of
 * the protocol endpoints and the issuer of every token the realm mints.
 */
class Realm
{
    private readonly string $url;

    private readonly Configuration $config;

    private ?JwksKeyResolver $keys = null;

    private ?TokenClient $tokens = null;

    public function __construct(
        string $url,
        private readonly string $clientId,
        #[SensitiveParameter] private readonly ?string $clientSecret = null,
        private readonly ?string $redirectUri = null,
        private readonly bool $basicAuth = false,
        private readonly ?CacheInterface $cache = null,
        private readonly ClientInterface $http = new Client,
    ) {
        $this->url = rtrim($url, '/');
        $this->config = new Configuration()->setHost($this->url);
    }

    public function authorization(): Authorization
    {
        return new Authorization(
            $this->config,
            $this->tokens(),
            $this->idTokens(),
            $this->clientId,
            $this->redirectUri ?? throw new LogicException('The authorization flow needs a redirect URI.'),
        );
    }

    public function tokens(): TokenClient
    {
        return $this->tokens ??= new TokenClient($this->config, $this->clientId, $this->clientSecret, $this->http, $this->cache, $this->basicAuth);
    }

    public function idTokens(): IdTokenValidator
    {
        return new IdTokenValidator($this->keys(), $this->url, $this->clientId);
    }

    public function logoutTokens(): LogoutTokenValidator
    {
        return new LogoutTokenValidator($this->keys(), $this->url, $this->clientId);
    }

    private function keys(): JwksKeyResolver
    {
        return $this->keys ??= new JwksKeyResolver(new DiscoveryApi($this->http, $this->config), $this->cache);
    }
}
