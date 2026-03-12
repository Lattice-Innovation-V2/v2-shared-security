package io.latticepay.security.it;

import io.latticepay.security.identity.MerchantAccessResolver;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Test implementation of {@link MerchantAccessResolver} for integration tests.
 * Returns configurable per-integrator merchant ID sets so tests can drive cache miss behavior.
 */
@ApplicationScoped
public class TestMerchantAccessResolver implements MerchantAccessResolver {

    private final Map<UUID, Set<UUID>> responses = new ConcurrentHashMap<>();

    /**
     * Sets the set of merchant IDs to return for the given integrator on cache miss.
     */
    public void setResponse(UUID integratorId, Set<UUID> merchantIds) {
        responses.put(integratorId, merchantIds != null ? Set.copyOf(merchantIds) : Set.of());
    }

    @Override
    public Set<UUID> resolveMerchantIds(UUID integratorId) {
        return responses.getOrDefault(integratorId, Set.of());
    }
}
