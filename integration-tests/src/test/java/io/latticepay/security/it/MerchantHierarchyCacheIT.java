package io.latticepay.security.it;

import io.latticepay.security.identity.MerchantHierarchyCache;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link MerchantHierarchyCache} against real Redis (Dev Services).
 * Verifies cache write/read, transaction semantics (setMerchantIds), cache miss → resolver → populate,
 * and eviction.
 */
@QuarkusTest
@TestProfile(MerchantHierarchyTestProfile.class)
@Execution(ExecutionMode.SAME_THREAD)
@DisplayName("MerchantHierarchyCache integration (Redis)")
class MerchantHierarchyCacheIT {

    @Inject
    MerchantHierarchyCache cache;

    @Inject
    TestMerchantAccessResolver testResolver;

    private static final UUID INTEGRATOR_A = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID INTEGRATOR_B = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID MERCHANT_1 = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static final UUID MERCHANT_2 = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static final UUID MERCHANT_3 = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");

    @Nested
    @DisplayName("setMerchantIds and getAccessibleMerchantIds")
    class SetAndGet {

        @Test
        @DisplayName("setMerchantIds then getAccessibleMerchantIds returns same set (cache write then read)")
        void setThenGet_returnsSameSet() {
            cache.setMerchantIds(INTEGRATOR_A, Set.of(MERCHANT_1, MERCHANT_2));
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_A);
            assertEquals(Set.of(MERCHANT_1, MERCHANT_2), result);
        }

        @Test
        @DisplayName("setMerchantIds with empty set then get triggers resolver")
        void setEmptyThenGet_usesResolver() {
            testResolver.setResponse(INTEGRATOR_A, Set.of(MERCHANT_1));
            cache.setMerchantIds(INTEGRATOR_A, Set.of());
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_A);
            assertEquals(Set.of(MERCHANT_1), result);
        }
    }

    @Nested
    @DisplayName("cache miss and population")
    class CacheMiss {

        @Test
        @DisplayName("getAccessibleMerchantIds on miss calls resolver and populates cache; second get is cache hit")
        void getOnMiss_populatesCache_thenHit() {
            testResolver.setResponse(INTEGRATOR_B, Set.of(MERCHANT_3));
            Set<UUID> first = cache.getAccessibleMerchantIds(INTEGRATOR_B);
            assertEquals(Set.of(MERCHANT_3), first);
            testResolver.setResponse(INTEGRATOR_B, Set.of()); // resolver now returns empty; cache should still return cached
            Set<UUID> second = cache.getAccessibleMerchantIds(INTEGRATOR_B);
            assertEquals(Set.of(MERCHANT_3), second);
        }
    }

    @Nested
    @DisplayName("evict")
    class Evict {

        @Test
        @DisplayName("evict removes entry; next get calls resolver")
        void evict_thenGet_callsResolver() {
            cache.setMerchantIds(INTEGRATOR_A, Set.of(MERCHANT_1, MERCHANT_2));
            cache.evict(INTEGRATOR_A);
            testResolver.setResponse(INTEGRATOR_A, Set.of(MERCHANT_3));
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_A);
            assertEquals(Set.of(MERCHANT_3), result);
        }
    }

    @Nested
    @DisplayName("bean registration")
    class BeanRegistration {

        @Test
        @DisplayName("MerchantHierarchyCache is injectable when profile enables merchant hierarchy")
        void cacheIsInjectable() {
            assertNotNull(cache);
        }

        @Test
        @DisplayName("TestMerchantAccessResolver is injectable")
        void testResolverIsInjectable() {
            assertNotNull(testResolver);
        }

        @Test
        @DisplayName("getAccessibleMerchantIds returns empty when resolver has no response")
        void getWithNoResolverResponse_returnsEmpty() {
            UUID unknown = UUID.randomUUID();
            Set<UUID> result = cache.getAccessibleMerchantIds(unknown);
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }
}
