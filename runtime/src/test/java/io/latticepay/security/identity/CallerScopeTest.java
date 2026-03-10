package io.latticepay.security.identity;

import jakarta.ws.rs.NotAuthorizedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CallerScope")
class CallerScopeTest {

    private static final String ROLE_PLATFORM_ADMIN = "platform_admin";
    private static final String ROLE_INTEGRATOR_ADMIN = "integrator_admin";
    private static final String ROLE_INTEGRATOR_READONLY = "integrator_readonly";
    private static final String ROLE_MERCHANT_ADMIN = "merchant_admin";
    private static final String ROLE_MERCHANT_READONLY = "merchant_readonly";
    private static final String EMAIL_ADMIN = "admin@latticepay.io";
    private static final String EMAIL_USER_EXT = "user@ext.com";
    private static final String PERM_MERCHANTS_READ = "merchants:read";
    private static final String PERM_MERCHANTS_WRITE = "merchants:write";
    private static final String PERM_PAYMENTS_READ = "payments:read";
    private static final String ENV_PRODUCTION = "production";

    @Nested
    @DisplayName("convenience methods")
    class ConvenienceMethods {

        @Test
        @DisplayName("isPlatformAdmin returns true for platform_admin role")
        void isPlatformAdminReturnsTrueForPlatformAdminRole() {
            var scope = new CallerScope(ROLE_PLATFORM_ADMIN, null, null, List.of(), null, EMAIL_ADMIN, CallerScope.AuthProvider.IAP);
            assertTrue(scope.isPlatformAdmin());
            assertFalse(scope.isIntegrator());
            assertFalse(scope.isMerchant());
            assertFalse(scope.isAnonymous());
        }

        @Test
        @DisplayName("isIntegratorAdmin returns true for integrator_admin role")
        void isIntegratorAdminReturnsTrueForIntegratorAdminRole() {
            UUID integratorId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_ADMIN, integratorId, null,
                    List.of(PERM_MERCHANTS_READ, PERM_MERCHANTS_WRITE), ENV_PRODUCTION, "user@external.com", CallerScope.AuthProvider.GCIP);
            assertFalse(scope.isPlatformAdmin());
            assertTrue(scope.isIntegratorAdmin());
            assertTrue(scope.isIntegrator());
            assertFalse(scope.isIntegratorReadonly());
            assertFalse(scope.isMerchant());
            assertFalse(scope.isAnonymous());
        }

        @Test
        @DisplayName("isIntegratorReadonly returns true for integrator_readonly role")
        void isIntegratorReadonlyReturnsTrueForIntegratorReadonlyRole() {
            UUID integratorId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_READONLY, integratorId, null,
                    List.of(PERM_MERCHANTS_READ), ENV_PRODUCTION, "readonly@external.com", CallerScope.AuthProvider.GCIP);
            assertFalse(scope.isPlatformAdmin());
            assertFalse(scope.isIntegratorAdmin());
            assertTrue(scope.isIntegratorReadonly());
            assertTrue(scope.isIntegrator());
            assertFalse(scope.isMerchant());
            assertFalse(scope.isAnonymous());
        }

        @Test
        @DisplayName("isMerchantAdmin returns true for merchant_admin role")
        void isMerchantAdminReturnsTrueForMerchantAdminRole() {
            UUID integratorId = UUID.randomUUID();
            UUID merchantId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_MERCHANT_ADMIN, integratorId, merchantId,
                    List.of(PERM_PAYMENTS_READ), ENV_PRODUCTION, "merchant@shop.com", CallerScope.AuthProvider.GCIP);
            assertFalse(scope.isPlatformAdmin());
            assertFalse(scope.isIntegrator());
            assertTrue(scope.isMerchantAdmin());
            assertTrue(scope.isMerchant());
            assertFalse(scope.isMerchantReadonly());
            assertFalse(scope.isAnonymous());
        }

        @Test
        @DisplayName("isMerchantReadonly returns true for merchant_readonly role")
        void isMerchantReadonlyReturnsTrueForMerchantReadonlyRole() {
            UUID integratorId = UUID.randomUUID();
            UUID merchantId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_MERCHANT_READONLY, integratorId, merchantId,
                    List.of(PERM_PAYMENTS_READ), ENV_PRODUCTION, "readonly@shop.com", CallerScope.AuthProvider.GCIP);
            assertFalse(scope.isPlatformAdmin());
            assertFalse(scope.isIntegrator());
            assertFalse(scope.isMerchantAdmin());
            assertTrue(scope.isMerchantReadonly());
            assertTrue(scope.isMerchant());
            assertFalse(scope.isAnonymous());
        }

        @Test
        @DisplayName("isAnonymous returns true when role is null")
        void isAnonymousReturnsTrueWhenRoleIsNull() {
            assertTrue(CallerScope.ANONYMOUS.isAnonymous());
            assertFalse(CallerScope.ANONYMOUS.isPlatformAdmin());
            assertFalse(CallerScope.ANONYMOUS.isIntegrator());
            assertFalse(CallerScope.ANONYMOUS.isMerchant());
            assertNull(CallerScope.ANONYMOUS.authProvider());
        }
    }

    @Nested
    @DisplayName("authProvider")
    class AuthProviderTests {

        @Test
        @DisplayName("authProvider is set correctly for each provider type")
        void authProviderIsSetCorrectly() {
            var iap = new CallerScope(ROLE_PLATFORM_ADMIN, null, null, List.of(), null, EMAIL_ADMIN, CallerScope.AuthProvider.IAP);
            assertEquals(CallerScope.AuthProvider.IAP, iap.authProvider());

            UUID intId = UUID.randomUUID();
            var gcip = new CallerScope(ROLE_INTEGRATOR_ADMIN, intId, null, List.of(), null, EMAIL_USER_EXT, CallerScope.AuthProvider.GCIP);
            assertEquals(CallerScope.AuthProvider.GCIP, gcip.authProvider());

            var wif = new CallerScope(ROLE_INTEGRATOR_ADMIN, intId, null, List.of(), null, EMAIL_USER_EXT, CallerScope.AuthProvider.WIF);
            assertEquals(CallerScope.AuthProvider.WIF, wif.authProvider());

            var dev = new CallerScope(ROLE_INTEGRATOR_ADMIN, intId, null, List.of(), null, "dev@test.com", CallerScope.AuthProvider.DEV);
            assertEquals(CallerScope.AuthProvider.DEV, dev.authProvider());
        }
    }

    @Nested
    @DisplayName("hasPermission")
    class HasPermission {

        @Test
        @DisplayName("returns true when permission is present")
        void returnsTrueWhenPermissionPresent() {
            UUID intId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_ADMIN, intId, null,
                    List.of(PERM_MERCHANTS_READ, PERM_MERCHANTS_WRITE, PERM_PAYMENTS_READ), ENV_PRODUCTION, EMAIL_USER_EXT, CallerScope.AuthProvider.GCIP);
            assertTrue(scope.hasPermission(PERM_MERCHANTS_READ));
            assertTrue(scope.hasPermission(PERM_MERCHANTS_WRITE));
            assertTrue(scope.hasPermission(PERM_PAYMENTS_READ));
        }

        @Test
        @DisplayName("returns false when permission is not present")
        void returnsFalseWhenPermissionNotPresent() {
            UUID intId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_READONLY, intId, null,
                    List.of(PERM_MERCHANTS_READ), ENV_PRODUCTION, EMAIL_USER_EXT, CallerScope.AuthProvider.GCIP);
            assertFalse(scope.hasPermission(PERM_MERCHANTS_WRITE));
        }

        @Test
        @DisplayName("returns false when permissions list is empty")
        void returnsFalseWhenPermissionsEmpty() {
            var scope = new CallerScope(ROLE_PLATFORM_ADMIN, null, null, List.of(), null, EMAIL_ADMIN, CallerScope.AuthProvider.IAP);
            assertFalse(scope.hasPermission("anything"));
        }
    }

    @Nested
    @DisplayName("requireIntegratorId")
    class RequireIntegratorId {

        @Test
        @DisplayName("returns integrator ID when present")
        void returnsIntegratorIdWhenPresent() {
            UUID integratorId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_ADMIN, integratorId, null,
                    List.of(), ENV_PRODUCTION, EMAIL_USER_EXT, CallerScope.AuthProvider.GCIP);
            assertEquals(integratorId, scope.requireIntegratorId());
        }

        @Test
        @DisplayName("throws NotAuthorizedException when integrator ID is null")
        void throwsNotAuthorizedExceptionWhenNull() {
            var scope = new CallerScope(ROLE_PLATFORM_ADMIN, null, null, List.of(), null, EMAIL_ADMIN, CallerScope.AuthProvider.IAP);
            assertThrows(NotAuthorizedException.class, scope::requireIntegratorId);
        }

        @Test
        @DisplayName("throws NotAuthorizedException for ANONYMOUS")
        void throwsNotAuthorizedExceptionForAnonymous() {
            assertThrows(NotAuthorizedException.class, CallerScope.ANONYMOUS::requireIntegratorId);
        }
    }

    @Nested
    @DisplayName("requireMerchantId")
    class RequireMerchantId {

        @Test
        @DisplayName("returns merchant ID when present")
        void returnsMerchantIdWhenPresent() {
            UUID integratorId = UUID.randomUUID();
            UUID merchantId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_MERCHANT_ADMIN, integratorId, merchantId,
                    List.of(), ENV_PRODUCTION, "merchant@shop.com", CallerScope.AuthProvider.GCIP);
            assertEquals(merchantId, scope.requireMerchantId());
        }

        @Test
        @DisplayName("throws NotAuthorizedException when merchant ID is null")
        void throwsNotAuthorizedExceptionWhenNullForMerchant() {
            UUID integratorId = UUID.randomUUID();
            var scope = new CallerScope(ROLE_INTEGRATOR_ADMIN, integratorId, null,
                    List.of(), null, EMAIL_USER_EXT, CallerScope.AuthProvider.GCIP);
            assertThrows(NotAuthorizedException.class, scope::requireMerchantId);
        }
    }
}
