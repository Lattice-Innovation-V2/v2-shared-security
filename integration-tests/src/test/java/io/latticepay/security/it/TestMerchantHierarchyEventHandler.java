package io.latticepay.security.it;

import io.latticepay.security.cache.MerchantHierarchyEvent;
import io.latticepay.security.cache.MerchantHierarchyEventHandler;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Test implementation of {@link MerchantHierarchyEventHandler} for integration tests.
 * Captures events in a blocking queue for test assertions.
 */
@ApplicationScoped
public class TestMerchantHierarchyEventHandler implements MerchantHierarchyEventHandler {

    private final BlockingQueue<MerchantHierarchyEvent> events = new LinkedBlockingQueue<>();

    @Override
    public void onMerchantCreated(MerchantHierarchyEvent event) {
        events.offer(event);
    }

    @Override
    public void onMerchantDeleted(MerchantHierarchyEvent event) {
        events.offer(event);
    }

    @Override
    public void onMerchantIntegratorChanged(MerchantHierarchyEvent event) {
        events.offer(event);
    }

    /**
     * Waits for and returns the next event received by this handler.
     * Returns null if no event is received within the timeout.
     */
    public MerchantHierarchyEvent awaitEvent(long timeout, TimeUnit unit) throws InterruptedException {
        return events.poll(timeout, unit);
    }

    /** Clears any buffered events. */
    public void clear() {
        events.clear();
    }
}
