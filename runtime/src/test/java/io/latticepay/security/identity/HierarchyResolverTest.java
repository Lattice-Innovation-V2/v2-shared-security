package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("HierarchyResolver")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HierarchyResolverTest {

    private static final String ROLE_PLATFORM_ADMIN = "platform_admin";
    private static final String ROLE_ADMIN = "admin";
    private static final String ROLE_INTEGRATOR_ADMIN = "integrator_admin";
    private static final String ROLE_INTEGRATOR_READONLY = "integrator_readonly";
    private static final String ROLE_MERCHANT_ADMIN = "merchant_admin";
    private static final String ROLE_MERCHANT_READONLY = "merchant_readonly";
    private static final String EMAIL_ADMIN = "admin@latticepay.io";
    private static final String EMAIL_USER_EXTERNAL = "user@external.com";
    private static final String PERM_MERCHANTS_READ = "merchants:read";
    private static final String PERM_MERCHANTS_WRITE = "merchants:write";
    private static final String TIER_PRODUCTION = "production";
    private static final String IAP_ISSUER = "https://cloud.google.com/iap";

    @Mock
    private IdentityUtils identityUtils;
    @Mock
    private MerchantHierarchyCache merchantHierarchyCache;
    @Mock
    private LatticeSecurityConfig config;
    @Mock
    private LatticeSecurityConfig.Wif wifConfig;
    @Mock
    private RoutingContext routingContext;
    @Mock
    private Instance<RoutingContext> routingContextInstance;
    @Mock
    private HttpServerRequest httpServerRequest;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private JsonWebToken jwt;
    @Mock
    private Principal nonJwtPrincipal;

    private HierarchyResolver resolver;

    @BeforeEach
    void setUp() {
        when(config.wif()).thenReturn(wifConfig);
        when(wifConfig.providerPrefix()).thenReturn("provider-integrator-");
        when(routingContext.request()).thenReturn(httpServerRequest);
        when(httpServerRequest.getHeader("X-Impersonate-Integrator-Id")).thenReturn(null);
        when(routingContextInstance.isResolvable()).thenReturn(true);
        when(routingContextInstance.get()).thenReturn(routingContext);
        resolver = new HierarchyResolver(identityUtils, merchantHierarchyCache, config, routingContextInstance);
    }

    @Nested
    @DisplayName("resolve")
    class Resolve {

        @Test
        @DisplayName("returns ANONYMOUS when securityContext is null")
        void returnsAnonymousWhenSecurityContextIsNull() {
            CallerScope result = resolver.resolve(null);

            assertSame(CallerScope.ANONYMOUS, result);
        }

        @Test
        @DisplayName("returns ANONYMOUS when principal is null")
        void returnsAnonymousWhenPrincipalIsNull() {
            when(securityContext.getUserPrincipal()).thenReturn(null);

            CallerScope result = resolver.resolve(securityContext);

            assertSame(CallerScope.ANONYMOUS, result);
        }

        @Test
        @DisplayName("returns ANONYMOUS when principal is not JWT")
        void returnsAnonymousWhenPrincipalIsNotJwt() {
            when(securityContext.getUserPrincipal()).thenReturn(nonJwtPrincipal);

            CallerScope result = resolver.resolve(securityContext);

            assertSame(CallerScope.ANONYMOUS, result);
        }

        @Test
        @DisplayName("returns platform_admin scope with IAP authProvider when token issuer is IAP")
        void returnsPlatformAdminScopeWithIapAuthProvider() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertNull(result.integratorId());
            assertNull(result.merchantId());
            assertEquals(List.of(), result.permissions());
            assertNull(result.tier());
            assertEquals(EMAIL_ADMIN, result.email());
            assertEquals(CallerScope.AuthProvider.IAP, result.authProvider());
        }

        @Test
        @DisplayName("returns platform_admin scope for admin role with IAP issuer")
        void returnsPlatformAdminScopeForAdminRole() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertEquals(CallerScope.AuthProvider.IAP, result.authProvider());
        }

        @Test
        @DisplayName("returns integrator_admin scope with GCIP authProvider and full claims")
        void returnsIntegratorAdminScopeWithGcipAuthProvider() {
            UUID integratorId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_USER_EXTERNAL);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of(PERM_MERCHANTS_READ, PERM_MERCHANTS_WRITE));
            when(identityUtils.getTier(jwt)).thenReturn(Optional.of(TIER_PRODUCTION));

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorAdmin());
            assertTrue(result.isIntegrator());
            assertEquals(integratorId, result.integratorId());
            assertNull(result.merchantId());
            assertEquals(List.of(PERM_MERCHANTS_READ, PERM_MERCHANTS_WRITE), result.permissions());
            assertEquals(TIER_PRODUCTION, result.tier());
            assertEquals(EMAIL_USER_EXTERNAL, result.email());
            assertEquals(CallerScope.AuthProvider.GCIP, result.authProvider());
        }

        @Test
        @DisplayName("returns integrator_readonly scope")
        void returnsIntegratorReadonlyScope() {
            UUID integratorId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_READONLY)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("readonly@external.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of(PERM_MERCHANTS_READ));
            when(identityUtils.getTier(jwt)).thenReturn(Optional.of(TIER_PRODUCTION));

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorReadonly());
            assertTrue(result.isIntegrator());
            assertEquals(CallerScope.AuthProvider.GCIP, result.authProvider());
        }

        @Test
        @DisplayName("returns merchant_admin scope with full claims")
        void returnsMerchantAdminScopeWithFullClaims() {
            UUID integratorId = UUID.randomUUID();
            UUID merchantId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_READONLY)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_MERCHANT_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("merchant@shop.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.of(merchantId));
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of("payments:read", "reporting:read"));
            when(identityUtils.getTier(jwt)).thenReturn(Optional.of(TIER_PRODUCTION));

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isMerchantAdmin());
            assertTrue(result.isMerchant());
            assertEquals(integratorId, result.integratorId());
            assertEquals(merchantId, result.merchantId());
            assertEquals(List.of("payments:read", "reporting:read"), result.permissions());
            assertEquals(TIER_PRODUCTION, result.tier());
            assertEquals(CallerScope.AuthProvider.GCIP, result.authProvider());
        }

        @Test
        @DisplayName("returns ANONYMOUS when no known role is present (fail-closed)")
        void returnsAnonymousWhenNoKnownRole() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_READONLY)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_MERCHANT_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_MERCHANT_READONLY)).thenReturn(false);
            when(identityUtils.getEmail(jwt)).thenReturn("unknown@example.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);

            CallerScope result = resolver.resolve(securityContext);

            assertSame(CallerScope.ANONYMOUS, result);
            assertTrue(result.isAnonymous());
            assertNull(result.integratorId());
        }
    }

    @Nested
    @DisplayName("Admin impersonation scope")
    class AdminImpersonationScope {

        @Test
        @DisplayName("platform_admin with X-Impersonate-Integrator-Id gets scoped integratorId")
        void platformAdminWithImpersonationHeader() {
            UUID impersonatedId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);
            when(httpServerRequest.getHeader("X-Impersonate-Integrator-Id")).thenReturn(impersonatedId.toString());

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertEquals(impersonatedId, result.integratorId());
            assertEquals(CallerScope.AuthProvider.IAP, result.authProvider());
        }

        @Test
        @DisplayName("platform_admin without impersonation header has null integratorId")
        void platformAdminWithoutImpersonationHeader() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);
            when(httpServerRequest.getHeader("X-Impersonate-Integrator-Id")).thenReturn(null);

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertNull(result.integratorId());
        }

        @Test
        @DisplayName("platform_admin with invalid UUID in impersonation header has null integratorId")
        void platformAdminWithInvalidUuidImpersonationHeader() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);
            when(httpServerRequest.getHeader("X-Impersonate-Integrator-Id")).thenReturn("not-a-uuid");

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertNull(result.integratorId());
        }

        @Test
        @DisplayName("platform_admin with blank impersonation header has null integratorId")
        void platformAdminWithBlankImpersonationHeader() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);
            when(httpServerRequest.getHeader("X-Impersonate-Integrator-Id")).thenReturn("   ");

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isPlatformAdmin());
            assertNull(result.integratorId());
        }
    }

    @Nested
    @DisplayName("WIF resolution")
    class WifResolution {

        @Test
        @DisplayName("returns WIF authProvider for WIF token with integrator_admin role")
        void returnsWifAuthProviderForWifToken() {
            UUID integratorId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("wif-user@external.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of(PERM_MERCHANTS_READ));
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorAdmin());
            assertEquals(CallerScope.AuthProvider.WIF, result.authProvider());
            assertEquals(integratorId, result.integratorId());
        }

        @Test
        @DisplayName("derives integrator ID from WIF provider when JWT claim is absent")
        void derivesIntegratorIdFromWifProviderWhenJwtClaimAbsent() {
            UUID integratorId = UUID.fromString("019478a1-0001-7000-8000-000000000001");
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("wif-user@external.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getWifProviderIdFromAudience(jwt)).thenReturn(Optional.of("provider-integrator-019478a1-0001-7000-8000-000000000001"));
            when(identityUtils.extractIntegratorIdFromProvider("provider-integrator-019478a1-0001-7000-8000-000000000001", "provider-integrator-"))
                    .thenReturn(Optional.of("019478a1-0001-7000-8000-000000000001"));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of(PERM_MERCHANTS_READ));
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorAdmin());
            assertEquals(CallerScope.AuthProvider.WIF, result.authProvider());
            assertEquals(integratorId, result.integratorId());
        }

        @Test
        @DisplayName("integrator ID is null when WIF provider extraction fails and JWT claim absent")
        void integratorIdNullWhenWifProviderExtractionFails() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("wif-user@external.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(true);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getWifProviderIdFromAudience(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorAdmin());
            assertEquals(CallerScope.AuthProvider.WIF, result.authProvider());
            assertNull(result.integratorId());
        }

        @Test
        @DisplayName("does not attempt WIF provider fallback for GCIP tokens")
        void doesNotAttemptWifFallbackForGcipToken() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_USER_EXTERNAL);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            CallerScope result = resolver.resolve(securityContext);

            assertTrue(result.isIntegratorAdmin());
            assertEquals(CallerScope.AuthProvider.GCIP, result.authProvider());
            assertNull(result.integratorId());
        }
    }

    @Nested
    @DisplayName("resolveAccessibleMerchantIds")
    class ResolveAccessibleMerchantIds {

        @Test
        @DisplayName("returns set from cache when integrator_admin with valid integrator_id")
        void returnsSetFromCacheWhenIntegratorAdminWithValidIntegratorId() {
            UUID integratorId = UUID.randomUUID();
            UUID merchant1 = UUID.randomUUID();
            UUID merchant2 = UUID.randomUUID();
            Set<UUID> expected = Set.of(merchant1, merchant2);

            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_USER_EXTERNAL);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());
            when(merchantHierarchyCache.getAccessibleMerchantIds(integratorId)).thenReturn(expected);

            Set<UUID> result = resolver.resolveAccessibleMerchantIds(securityContext);

            assertEquals(expected, result);
            verify(merchantHierarchyCache).getAccessibleMerchantIds(integratorId);
        }

        @Test
        @DisplayName("throws NotAuthorizedException when integrator has null integrator_id")
        void throwsNotAuthorizedExceptionWhenIntegratorHasNullIntegratorId() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_USER_EXTERNAL);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.empty());
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            assertThrows(jakarta.ws.rs.NotAuthorizedException.class,
                    () -> resolver.resolveAccessibleMerchantIds(securityContext));
        }

        @Test
        @DisplayName("returns empty set when platform_admin caller")
        void returnsEmptySetWhenPlatformAdminCaller() {
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn(EMAIL_ADMIN);
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(jwt.getIssuer()).thenReturn(IAP_ISSUER);

            Set<UUID> result = resolver.resolveAccessibleMerchantIds(securityContext);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("returns empty set when merchant_admin caller")
        void returnsEmptySetWhenMerchantAdminCaller() {
            UUID integratorId = UUID.randomUUID();
            UUID merchantId = UUID.randomUUID();
            when(securityContext.getUserPrincipal()).thenReturn(jwt);
            when(securityContext.isUserInRole(ROLE_PLATFORM_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_ADMIN)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_INTEGRATOR_READONLY)).thenReturn(false);
            when(securityContext.isUserInRole(ROLE_MERCHANT_ADMIN)).thenReturn(true);
            when(identityUtils.getEmail(jwt)).thenReturn("merchant@shop.com");
            when(identityUtils.isWifToken(jwt)).thenReturn(false);
            when(identityUtils.isInternalUser(jwt)).thenReturn(false);
            when(identityUtils.getIntegratorId(jwt)).thenReturn(Optional.of(integratorId));
            when(identityUtils.getMerchantId(jwt)).thenReturn(Optional.of(merchantId));
            when(identityUtils.getPermissions(jwt)).thenReturn(List.of());
            when(identityUtils.getTier(jwt)).thenReturn(Optional.empty());

            Set<UUID> result = resolver.resolveAccessibleMerchantIds(securityContext);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("returns empty set when anonymous caller")
        void returnsEmptySetWhenAnonymousCaller() {
            Set<UUID> result = resolver.resolveAccessibleMerchantIds(null);

            assertTrue(result.isEmpty());
        }
    }
}
