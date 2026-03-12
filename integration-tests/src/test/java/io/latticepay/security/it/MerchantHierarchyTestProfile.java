package io.latticepay.security.it;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Test profile that enables the merchant hierarchy cache with Redis (Dev Services).
 * Use with {@code @TestProfile(MerchantHierarchyTestProfile.class)} for tests that need
 * {@link io.latticepay.security.identity.MerchantHierarchyCache} and real Redis.
 */
public class MerchantHierarchyTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "latticepay.security.merchant-hierarchy.enabled", "true",
                "latticepay.security.merchant-hierarchy.redis-key-prefix", "latticepay:it:hierarchy",
                "latticepay.security.merchant-hierarchy.ttl", "PT5M");
    }
}
