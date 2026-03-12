package io.latticepay.security.it;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Test profile that enables both publisher and subscriber for pub/sub integration tests.
 */
public class MerchantHierarchyPubSubTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "latticepay.security.merchant-hierarchy.enabled", "true",
                "latticepay.security.merchant-hierarchy.redis-key-prefix", "latticepay:it:pubsub",
                "latticepay.security.merchant-hierarchy.ttl", "PT5M",
                "latticepay.security.merchant-hierarchy.publisher-enabled", "true",
                "latticepay.security.merchant-hierarchy.subscriber-enabled", "true",
                "latticepay.security.merchant-hierarchy.pubsub-channel", "latticepay:it:merchant-hierarchy:events");
    }
}
