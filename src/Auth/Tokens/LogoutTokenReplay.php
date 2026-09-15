<?php

declare(strict_types=1);

namespace Lock\Client\Auth\Tokens;

use Psr\SimpleCache\CacheInterface;

/**
 * Back-Channel Logout §2.6 replay protection: each logout token jti is
 * accepted once.
 */
class LogoutTokenReplay
{
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly int $retention = 7200,
    ) {}

    /**
     * False when the jti was already consumed. It is remembered until the later
     * of the token's exp and the retention window, which outlives the span in
     * which the validator would still accept the token.
     */
    public function consume(string $jti, int $expiresAt): bool
    {
        $key = 'lock.logout-jti.'.sha1($jti);

        // PSR-16 has no atomic add, so two concurrent deliveries of one token can both pass.
        if ($this->cache->has($key)) {
            return false;
        }

        return $this->cache->set($key, true, max($expiresAt - time(), $this->retention));
    }
}
