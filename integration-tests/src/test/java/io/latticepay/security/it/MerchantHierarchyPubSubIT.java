package io.latticepay.security.it;

import io.latticepay.security.cache.MerchantHierarchyEvent;
import io.latticepay.security.cache.MerchantHierarchyEventPublisher;
import io.latticepay.security.identity.CallerScope;
import io.latticepay.security.identity.HierarchyResolver;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration test for merchant hierarchy pub/sub round-trip.
 * Publishes events and verifies the subscriber dispatches them to the handler.
 */
@QuarkusTest
@TestProfile(MerchantHierarchyPubSubTestProfile.class)
@Execution(ExecutionMode.SAME_THREAD)
@DisplayName("MerchantHierarchy Pub/Sub integration (Redis)")
class MerchantHierarchyPubSubIT {

    private static final String EXPECTED_EVENT_RECEIVED_MSG = "Expected event to be received by handler";

    @Inject
    MerchantHierarchyEventPublisher publisher;

    @Inject
    TestMerchantHierarchyEventHandler testHandler;

    @Inject
    HierarchyResolver hierarchyResolver;

    @Inject
    TestMerchantAccessResolver testMerchantAccessResolver;

    @BeforeEach
    void clearHandlerQueue() {
        testHandler.clear();
    }

    @Test
    @DisplayName("publish MERCHANT_CREATED event → subscriber dispatches to handler")
    void publishMerchantCreatedDispatchesToHandler() throws InterruptedException {
        UUID merchantId = UUID.randomUUID();
        UUID integratorId = UUID.randomUUID();

        publisher.publishMerchantCreated(merchantId, integratorId);

        MerchantHierarchyEvent event = testHandler.awaitEvent(5, TimeUnit.SECONDS);
        assertNotNull(event, EXPECTED_EVENT_RECEIVED_MSG);
        assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_CREATED, event.type());
        assertEquals(merchantId, event.merchantId());
        assertEquals(integratorId, event.integratorId());
    }

    @Test
    @DisplayName("publish MERCHANT_DELETED event → subscriber dispatches to handler")
    void publishMerchantDeletedDispatchesToHandler() throws InterruptedException {
        UUID merchantId = UUID.randomUUID();
        UUID integratorId = UUID.randomUUID();

        publisher.publishMerchantDeleted(merchantId, integratorId);

        MerchantHierarchyEvent event = testHandler.awaitEvent(5, TimeUnit.SECONDS);
        assertNotNull(event, EXPECTED_EVENT_RECEIVED_MSG);
        assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_DELETED, event.type());
        assertEquals(merchantId, event.merchantId());
        assertEquals(integratorId, event.integratorId());
    }

    @Test
    @DisplayName("publish MERCHANT_INTEGRATOR_CHANGED event → subscriber dispatches to handler")
    void publishMerchantIntegratorChangedDispatchesToHandler() throws InterruptedException {
        UUID merchantId = UUID.randomUUID();
        UUID newIntegratorId = UUID.randomUUID();
        UUID previousIntegratorId = UUID.randomUUID();

        publisher.publishMerchantIntegratorChanged(merchantId, newIntegratorId, previousIntegratorId);

        MerchantHierarchyEvent event = testHandler.awaitEvent(5, TimeUnit.SECONDS);
        assertNotNull(event, EXPECTED_EVENT_RECEIVED_MSG);
        assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_INTEGRATOR_CHANGED, event.type());
        assertEquals(merchantId, event.merchantId());
        assertEquals(newIntegratorId, event.integratorId());
        assertEquals(previousIntegratorId, event.previousIntegratorId());
    }

    @Nested
    @DisplayName("Access control (caller type and authorization)")
    class AccessControl {

        private static final UUID PARENT_INTEGRATOR_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
        private static final UUID CHILD_INTEGRATOR_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
        private static final UUID MERCHANT_ID = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        private static final UUID MERCHANT_INTEGRATOR_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
        private static final UUID MERCHANT_1 = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        private static final UUID MERCHANT_2 = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
        private static final UUID MERCHANT_3 = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");

        private static final String ROLE_PLATFORM_ADMIN = "platform_admin";
        private static final String ROLE_ADMIN = "admin";
        private static final String ROLE_INTEGRATOR_ADMIN = "integrator_admin";
        private static final String CLAIM_EMAIL = "email";
        private static final String CLAIM_INTEGRATOR_ID = "integrator_id";
        private static final String CLAIM_MERCHANT_ID = "merchant_id";

        @Test
        @DisplayName("admin caller: scope is platform_admin, accessible merchant IDs empty (unrestricted)")
        void adminCallerScopeIsPlatformAdminAccessibleMerchantIdsEmpty() {
            SecurityContext secCtx = mock(SecurityContext.class);
            JsonWebToken jwt = mock(JsonWebToken.class);
            when(secCtx.getUserPrincipal()).thenReturn(jwt);
            when(secCtx.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("admin@latticepay.io");

            CallerScope scope = hierarchyResolver.resolve(secCtx);
            assertTrue(scope.isPlatformAdmin(), "Admin caller should resolve to platform_admin scope");
            assertNull(scope.integratorId());
            Set<UUID> merchantIds = hierarchyResolver.resolveAccessibleMerchantIds(secCtx);
            assertNotNull(merchantIds);
            assertTrue(merchantIds.isEmpty(), "Admin gets empty set (unrestricted convention)");
        }

        @Test
        @DisplayName("parent integrator: scope is integrator, accessible merchant IDs from cache (full subtree)")
        void parentIntegratorScopeIsIntegratorAccessibleMerchantIdsFromCache() {
            testMerchantAccessResolver.setResponse(PARENT_INTEGRATOR_ID, Set.of(MERCHANT_1, MERCHANT_2));

            SecurityContext secCtx = mock(SecurityContext.class);
            JsonWebToken jwt = mock(JsonWebToken.class);
            when(secCtx.getUserPrincipal()).thenReturn(jwt);
            when(secCtx.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("parent@integrator.com");
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(PARENT_INTEGRATOR_ID.toString());

            CallerScope scope = hierarchyResolver.resolve(secCtx);
            assertTrue(scope.isIntegrator(), "Parent integrator should resolve to integrator scope");
            assertEquals(PARENT_INTEGRATOR_ID, scope.integratorId());
            Set<UUID> merchantIds = hierarchyResolver.resolveAccessibleMerchantIds(secCtx);
            assertEquals(Set.of(MERCHANT_1, MERCHANT_2), merchantIds);
        }

        @Test
        @DisplayName("child integrator: scope is integrator, accessible merchant IDs from cache (direct only)")
        void childIntegratorScopeIsIntegratorAccessibleMerchantIdsFromCache() {
            testMerchantAccessResolver.setResponse(CHILD_INTEGRATOR_ID, Set.of(MERCHANT_3));

            SecurityContext secCtx = mock(SecurityContext.class);
            JsonWebToken jwt = mock(JsonWebToken.class);
            when(secCtx.getUserPrincipal()).thenReturn(jwt);
            when(secCtx.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("child@integrator.com");
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(CHILD_INTEGRATOR_ID.toString());

            CallerScope scope = hierarchyResolver.resolve(secCtx);
            assertTrue(scope.isIntegrator(), "Child integrator should resolve to integrator scope");
            assertEquals(CHILD_INTEGRATOR_ID, scope.integratorId());
            Set<UUID> merchantIds = hierarchyResolver.resolveAccessibleMerchantIds(secCtx);
            assertEquals(Set.of(MERCHANT_3), merchantIds);
        }

        @Test
        @DisplayName("merchant caller: scope is merchant, accessible merchant IDs empty (self-access via requireMerchantId)")
        void merchantCallerScopeIsMerchantAccessibleMerchantIdsEmpty() {
            SecurityContext secCtx = mock(SecurityContext.class);
            JsonWebToken jwt = mock(JsonWebToken.class);
            when(secCtx.getUserPrincipal()).thenReturn(jwt);
            when(secCtx.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(false);
            when(secCtx.isUserInRole("integrator_readonly")).thenReturn(false);
            when(secCtx.isUserInRole("merchant_admin")).thenReturn(true);
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("merchant@shop.com");
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(MERCHANT_INTEGRATOR_ID.toString());
            when(jwt.getClaim(CLAIM_MERCHANT_ID)).thenReturn(MERCHANT_ID.toString());

            CallerScope scope = hierarchyResolver.resolve(secCtx);
            assertTrue(scope.isMerchant(), "Merchant caller should resolve to merchant scope");
            assertEquals(MERCHANT_ID, scope.merchantId());
            assertEquals(MERCHANT_INTEGRATOR_ID, scope.integratorId());
            Set<UUID> merchantIds = hierarchyResolver.resolveAccessibleMerchantIds(secCtx);
            assertNotNull(merchantIds);
            assertTrue(merchantIds.isEmpty(), "Merchant gets empty set (self-access via requireMerchantId)");
        }

        @Test
        @DisplayName("anonymous caller: scope is ANONYMOUS, accessible merchant IDs empty")
        void anonymousCallerScopeIsAnonymousAccessibleMerchantIdsEmpty() {
            SecurityContext secCtx = mock(SecurityContext.class);
            when(secCtx.getUserPrincipal()).thenReturn(null);

            CallerScope scope = hierarchyResolver.resolve(secCtx);
            assertSame(CallerScope.ANONYMOUS, scope);
            Set<UUID> merchantIds = hierarchyResolver.resolveAccessibleMerchantIds(secCtx);
            assertNotNull(merchantIds);
            assertTrue(merchantIds.isEmpty());
        }
    }
}
