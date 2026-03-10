package io.latticepay.security.cache;

/**
 * SPI interface for handling merchant hierarchy events.
 * Consuming services (e.g., integrator-service) implement this to react to
 * merchant CRUD events received via Redis pub/sub.
 */
public interface MerchantHierarchyEventHandler {

    /** Called when a new merchant is created. */
    void onMerchantCreated(MerchantHierarchyEvent event);

    /** Called when a merchant is deleted. */
    void onMerchantDeleted(MerchantHierarchyEvent event);

    /** Called when a merchant's integrator assignment changes. */
    void onMerchantIntegratorChanged(MerchantHierarchyEvent event);

    /**
     * Called when an event has an unknown type (e.g. from a newer publisher).
     * Default is no-op; override to handle or throw to surface the unexpected value.
     *
     * @param event   deserialized event (type may be an unknown enum constant)
     * @param rawJson original message JSON for diagnostics
     */
    default void onUnknownEvent(MerchantHierarchyEvent event, String rawJson) {
        // no-op by default
    }
}
