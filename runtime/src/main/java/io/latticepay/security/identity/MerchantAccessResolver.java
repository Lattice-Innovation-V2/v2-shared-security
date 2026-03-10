package io.latticepay.security.identity;

import java.util.Set;
import java.util.UUID;

/**
 * SPI for resolving the set of merchant IDs accessible to an integrator.
 *
 * Consuming services implement this interface with their database or service-to-service
 * lookup. It is called by {@link MerchantHierarchyCache} on Redis cache miss as the
 * fallback data source.
 *
 * The implementation must apply hierarchy rules based on {@code parentId} relationships:
 *
 * - **Top-level integrator** ({@code parentId = null}): return all merchants with
 *   {@code parentId = integratorId} plus all merchants under child sub-integrators
 *   (full subtree).
 * - **Sub-integrator** ({@code parentId != null}): return only merchants with
 *   {@code parentId = integratorId} (direct children only).
 *
 * @see MerchantHierarchyCache
 * @see HierarchyResolver#resolveAccessibleMerchantIds
 */
public interface MerchantAccessResolver {

    /**
     * Resolves the set of merchant IDs accessible to the given integrator.
     *
     * @param integratorId the integrator's entity ID (never null)
     * @return the set of accessible merchant IDs (never null, may be empty)
     */
    Set<UUID> resolveMerchantIds(UUID integratorId);
}
