package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Redis-backed cache for integrator-to-merchant ID mappings.
 *
 * Used by {@link HierarchyResolver#resolveAccessibleMerchantIds} to resolve the set of
 * merchant IDs an integrator may access. On cache miss, delegates to {@link MerchantAccessResolver}.
 *
 * Consuming services must call write methods ({@link #addMerchant}, {@link #removeMerchant},
 * {@link #setMerchantIds}, {@link #evict}) on entity lifecycle events to keep the cache consistent.
 */
@ApplicationScoped
public class MerchantHierarchyCache {

    private final LatticeSecurityConfig config;
    private final Instance<RedisDataSource> redisInstance;
    private final Instance<MerchantAccessResolver> resolverInstance;

    private final boolean enabled;
    private final String keyPrefix;
    private final Duration ttl;

    public MerchantHierarchyCache(
            LatticeSecurityConfig config,
            Instance<RedisDataSource> redisInstance,
            Instance<MerchantAccessResolver> resolverInstance) {
        this.config = config;
        this.redisInstance = redisInstance;
        this.resolverInstance = resolverInstance;

        var mh = config.merchantHierarchy();
        this.enabled = mh.enabled();
        this.keyPrefix = mh.redisKeyPrefix();
        this.ttl = mh.ttl();

        if (enabled && !redisInstance.isResolvable()) {
            throw new IllegalStateException(
                    "latticepay.security.merchant-hierarchy.enabled=true but Redis is not available. "
                            + "Add quarkus-redis-client and configure quarkus.redis.hosts.");
        }
    }

    /**
     * Returns the set of merchant IDs accessible to the given integrator.
     * Checks Redis first; on miss, resolves via SPI and populates the cache.
     */
    public Set<UUID> getAccessibleMerchantIds(UUID integratorId) {
        if (!enabled) {
            return fallbackResolve(integratorId);
        }

        String key = buildKey(integratorId);
        var sets = redisInstance.get().set(String.class);
        Set<String> cached = sets.smembers(key);

        if (!cached.isEmpty()) {
            return toUuidSet(cached);
        }

        Set<UUID> resolved = fallbackResolve(integratorId);
        if (!resolved.isEmpty()) {
            sets.sadd(key, resolved.stream().map(UUID::toString).toArray(String[]::new));
            redisInstance.get().key().expire(key, ttl);
        }
        return resolved;
    }

    /** Adds a merchant to an integrator's cached set. */
    public void addMerchant(UUID integratorId, UUID merchantId) {
        if (!enabled) {
            return;
        }
        String key = buildKey(integratorId);
        redisInstance.get().set(String.class).sadd(key, merchantId.toString());
        redisInstance.get().key().expire(key, ttl);
    }

    /** Removes a merchant from an integrator's cached set. */
    public void removeMerchant(UUID integratorId, UUID merchantId) {
        if (!enabled) {
            return;
        }
        String key = buildKey(integratorId);
        redisInstance.get().set(String.class).srem(key, merchantId.toString());
    }

    /**
     * Replaces the integrator's cached set with the given merchant IDs.
     * Runs DEL + SADD (when non-empty) + EXPIRE inside a single Redis transaction (MULTI/EXEC)
     * so that key replacement cannot interleave between threads and the TTL is set only after the new set is created.
     */
    public void setMerchantIds(UUID integratorId, Set<UUID> merchantIds) {
        if (!enabled) {
            return;
        }
        String key = buildKey(integratorId);
        String[] members = merchantIds.stream().map(UUID::toString).toArray(String[]::new);
        redisInstance.get().withTransaction(tx -> {
            tx.key().del(key);
            if (members.length > 0) {
                tx.set(String.class).sadd(key, members);
                tx.key().expire(key, ttl);
            }
        });
    }

    /** Evicts the integrator's cache entry. Call when hierarchy changes (e.g. parent subtree stale). */
    public void evict(UUID integratorId) {
        if (!enabled) {
            return;
        }
        String key = buildKey(integratorId);
        redisInstance.get().key().del(key);
    }

    private Set<UUID> fallbackResolve(UUID integratorId) {
        if (!resolverInstance.isResolvable()) {
            throw new IllegalStateException(
                    "No MerchantAccessResolver implementation found. "
                            + "Provide a CDI bean implementing MerchantAccessResolver.");
        }
        return resolverInstance.get().resolveMerchantIds(integratorId);
    }

    private String buildKey(UUID integratorId) {
        return keyPrefix + ":" + integratorId + ":merchants";
    }

    private static Set<UUID> toUuidSet(Set<String> strings) {
        if (strings == null || strings.isEmpty()) {
            return Set.of();
        }
        return strings.stream()
                .map(s -> {
                    try {
                        return UUID.fromString(s);
                    } catch (IllegalArgumentException ignored) {
                        return null;
                    }
                })
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());
    }
}
