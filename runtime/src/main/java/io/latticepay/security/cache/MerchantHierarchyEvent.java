package io.latticepay.security.cache;

import java.time.Instant;
import java.util.UUID;

/**
 * Event published over Redis pub/sub when merchant hierarchy changes.
 * Shared between publisher (merchant-service) and subscriber (integrator-service).
 */
public record MerchantHierarchyEvent(
        EventType type,
        UUID merchantId,
        UUID integratorId,
        UUID previousIntegratorId,
        Instant timestamp
) {

    public enum EventType {
        MERCHANT_CREATED,
        MERCHANT_DELETED,
        MERCHANT_INTEGRATOR_CHANGED
    }
}
