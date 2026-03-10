package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@DisplayName("IdentityUtils")
@ExtendWith(MockitoExtension.class)
class IdentityUtilsTest {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_INTEGRATOR_ID = "integrator_id";
    private static final String CLAIM_MERCHANT_ID = "merchant_id";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String WIF_PROVIDER_PREFIX = "provider-integrator-";
    private static final String WIF_PROVIDER_ID_SAMPLE = "provider-integrator-int_abc123";

    @Mock
    private LatticeSecurityConfig mockConfig;
    @Mock
    private LatticeSecurityConfig.ForwardedAuth mockForwardedAuth;
    @Mock
    private LatticeSecurityConfig.Iap mockIap;
    @Mock
    private LatticeSecurityConfig.Gcip mockGcip;
    @Mock
    private LatticeSecurityConfig.GcpServiceAuth mockGcpServiceAuth;
    @Mock
    private JsonWebToken jwt;

    private IdentityUtils identityUtils;

    @BeforeEach
    void setUp() {
        lenient().when(mockConfig.internalDomain()).thenReturn("@latticepay.io");
        lenient().when(mockConfig.roleClaim()).thenReturn("role");
        lenient().when(mockConfig.forwardedAuth()).thenReturn(mockForwardedAuth);
        lenient().when(mockConfig.iap()).thenReturn(mockIap);
        lenient().when(mockConfig.gcip()).thenReturn(mockGcip);
        lenient().when(mockConfig.gcpServiceAuth()).thenReturn(mockGcpServiceAuth);
        identityUtils = new IdentityUtils(mockConfig);
    }

    @Nested
    @DisplayName("isInternalUser")
    class IsInternalUserTests {

        @Test
        @DisplayName("should return true when email ends with @latticepay.io")
        void shouldReturnTrueWhenEmailEndsWithLatticepayIo() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@latticepay.io");

            assertTrue(identityUtils.isInternalUser(jwt));
        }

        @Test
        @DisplayName("should return true when email ends with @latticepay.io (case insensitive)")
        void shouldReturnTrueWhenEmailEndsWithLatticepayIoCaseInsensitive() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@LATTICEPAY.IO");

            assertTrue(identityUtils.isInternalUser(jwt));
        }

        @Test
        @DisplayName("should return false when email does not end with @latticepay.io")
        void shouldReturnFalseWhenEmailDoesNotEndWithLatticepayIo() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@external.com");

            assertFalse(identityUtils.isInternalUser(jwt));
        }

        @Test
        @DisplayName("should return false when email is null")
        void shouldReturnFalseWhenEmailIsNull() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn(null);
            when(jwt.getName()).thenReturn(null);

            assertFalse(identityUtils.isInternalUser(jwt));
        }

        @Test
        @DisplayName("should return false when jwt is null")
        void shouldReturnFalseWhenJwtIsNull() {
            assertFalse(identityUtils.isInternalUser(null));
        }
    }

    @Nested
    @DisplayName("getEmail")
    class GetEmailTests {

        @Test
        @DisplayName("should return email claim")
        void shouldReturnEmailClaimWhenPresent() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@test.com");

            assertEquals("user@test.com", identityUtils.getEmail(jwt));
        }

        @Test
        @DisplayName("should fallback to name when email claim is null")
        void shouldFallbackToNameWhenEmailClaimIsNull() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn(null);
            when(jwt.getName()).thenReturn("fallback@test.com");

            assertEquals("fallback@test.com", identityUtils.getEmail(jwt));
        }

        @Test
        @DisplayName("should return null when jwt is null")
        void shouldReturnNullWhenJwtIsNull() {
            assertNull(identityUtils.getEmail(null));
        }
    }

    @Nested
    @DisplayName("getIntegratorId")
    class GetIntegratorIdTests {

        @Test
        @DisplayName("should return integrator_id claim as UUID")
        void shouldReturnIntegratorIdClaimAsUuidWhenPresent() {
            UUID expectedId = UUID.randomUUID();
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(expectedId.toString());

            Optional<UUID> result = identityUtils.getIntegratorId(jwt);

            assertTrue(result.isPresent());
            assertEquals(expectedId, result.get());
        }

        @Test
        @DisplayName("should return empty when integrator_id claim is null")
        void shouldReturnEmptyWhenClaimIsNull() {
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(null);

            Optional<UUID> result = identityUtils.getIntegratorId(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when integrator_id is not a valid UUID")
        void shouldReturnEmptyWhenClaimIsInvalidUuid() {
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn("not-a-valid-uuid");

            Optional<UUID> result = identityUtils.getIntegratorId(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when jwt is null")
        void shouldReturnEmptyWhenJwtIsNull() {
            Optional<UUID> result = identityUtils.getIntegratorId(null);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("getMerchantId")
    class GetMerchantIdTests {

        @Test
        @DisplayName("should return merchant_id claim as UUID")
        void shouldReturnMerchantIdClaimAsUuid() {
            UUID expectedId = UUID.randomUUID();
            when(jwt.getClaim(CLAIM_MERCHANT_ID)).thenReturn(expectedId.toString());

            Optional<UUID> result = identityUtils.getMerchantId(jwt);

            assertTrue(result.isPresent());
            assertEquals(expectedId, result.get());
        }

        @Test
        @DisplayName("should return empty when merchant_id claim is null")
        void shouldReturnEmptyWhenClaimIsNull() {
            when(jwt.getClaim(CLAIM_MERCHANT_ID)).thenReturn(null);

            Optional<UUID> result = identityUtils.getMerchantId(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when merchant_id is not a valid UUID")
        void shouldReturnEmptyWhenClaimIsInvalidUuid() {
            when(jwt.getClaim(CLAIM_MERCHANT_ID)).thenReturn("not-a-valid-uuid");

            Optional<UUID> result = identityUtils.getMerchantId(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when jwt is null")
        void shouldReturnEmptyWhenJwtIsNullForMerchant() {
            Optional<UUID> result = identityUtils.getMerchantId(null);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("getPermissions")
    class GetPermissionsTests {

        @Test
        @DisplayName("should return permissions list when present")
        void shouldReturnPermissionsListWhenPresent() {
            when(jwt.getClaim(CLAIM_PERMISSIONS)).thenReturn(List.of("merchants:read", "merchants:write", "payments:read"));

            List<String> result = identityUtils.getPermissions(jwt);

            assertEquals(3, result.size());
            assertTrue(result.contains("merchants:read"));
            assertTrue(result.contains("merchants:write"));
            assertTrue(result.contains("payments:read"));
        }

        @Test
        @DisplayName("should return empty list when permissions claim is null")
        void shouldReturnEmptyListWhenClaimIsNull() {
            when(jwt.getClaim(CLAIM_PERMISSIONS)).thenReturn(null);

            List<String> result = identityUtils.getPermissions(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty list when jwt is null")
        void shouldReturnEmptyListWhenJwtIsNull() {
            List<String> result = identityUtils.getPermissions(null);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty list when claim is not a collection")
        void shouldReturnEmptyListWhenClaimIsNotCollection() {
            when(jwt.getClaim(CLAIM_PERMISSIONS)).thenReturn("not-a-list");

            List<String> result = identityUtils.getPermissions(jwt);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("getTier")
    class GetTierTests {

        @Test
        @DisplayName("should return tier claim when present")
        void shouldReturnTierClaimWhenPresent() {
            when(jwt.getClaim("tier")).thenReturn("production");

            Optional<String> result = identityUtils.getTier(jwt);

            assertTrue(result.isPresent());
            assertEquals("production", result.get());
        }

        @Test
        @DisplayName("should return sandbox tier")
        void shouldReturnSandboxTier() {
            when(jwt.getClaim("tier")).thenReturn("sandbox");

            Optional<String> result = identityUtils.getTier(jwt);

            assertTrue(result.isPresent());
            assertEquals("sandbox", result.get());
        }

        @Test
        @DisplayName("should return empty when tier claim is null")
        void shouldReturnEmptyWhenTierClaimIsNull() {
            when(jwt.getClaim("tier")).thenReturn(null);

            Optional<String> result = identityUtils.getTier(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when jwt is null")
        void shouldReturnEmptyWhenJwtIsNullForTier() {
            Optional<String> result = identityUtils.getTier(null);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("getRole")
    class GetRoleTests {

        @Test
        @DisplayName("should return role claim when present")
        void shouldReturnRoleClaimWhenPresent() {
            when(jwt.getClaim("role")).thenReturn("integrator_admin");

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isPresent());
            assertEquals("integrator_admin", result.get());
        }

        @Test
        @DisplayName("should return legacy integrator role")
        void shouldReturnLegacyIntegratorRole() {
            when(jwt.getClaim("role")).thenReturn("integrator");

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isPresent());
            assertEquals("integrator", result.get());
        }

        @Test
        @DisplayName("should return empty when role claim is null")
        void shouldReturnEmptyWhenRoleClaimIsNull() {
            when(jwt.getClaim("role")).thenReturn(null);

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when jwt is null")
        void shouldReturnEmptyWhenJwtIsNullForRole() {
            Optional<String> result = identityUtils.getRole(null);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should fall back to gcip.firebase.sign_in_attributes.role when top-level absent")
        void shouldFallBackToGcipNestedRole() {
            when(jwt.getClaim("role")).thenReturn(null);
            Map<String, Object> attrs = Map.of("role", "integrator_admin");
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            when(jwt.getClaim("gcip")).thenReturn(gcip);

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isPresent());
            assertEquals("integrator_admin", result.get());
        }

        @Test
        @DisplayName("should prefer top-level role over nested gcip role")
        void shouldPreferTopLevelRoleOverGcipNested() {
            when(jwt.getClaim("role")).thenReturn("platform_admin");
            Map<String, Object> attrs = Map.of("role", "integrator_admin");
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            lenient().when(jwt.getClaim("gcip")).thenReturn(gcip);

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isPresent());
            assertEquals("platform_admin", result.get());
        }

        @Test
        @DisplayName("should return empty when neither top-level nor gcip role present")
        void shouldReturnEmptyWhenNeitherTopLevelNorGcipRolePresent() {
            when(jwt.getClaim("role")).thenReturn(null);
            when(jwt.getClaim("gcip")).thenReturn(null);

            Optional<String> result = identityUtils.getRole(jwt);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("GCIP nested claim fallback")
    class GcipNestedClaimTests {

        @Test
        @DisplayName("getIntegratorId falls back to gcip nested claim")
        void getIntegratorIdFallsBackToGcipNested() {
            UUID expectedId = UUID.randomUUID();
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(null);
            Map<String, Object> attrs = Map.of("integrator_id", expectedId.toString());
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            when(jwt.getClaim("gcip")).thenReturn(gcip);

            Optional<UUID> result = identityUtils.getIntegratorId(jwt);

            assertTrue(result.isPresent());
            assertEquals(expectedId, result.get());
        }

        @Test
        @DisplayName("getMerchantId falls back to gcip nested claim")
        void getMerchantIdFallsBackToGcipNested() {
            UUID expectedId = UUID.randomUUID();
            when(jwt.getClaim(CLAIM_MERCHANT_ID)).thenReturn(null);
            Map<String, Object> attrs = Map.of("merchant_id", expectedId.toString());
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            when(jwt.getClaim("gcip")).thenReturn(gcip);

            Optional<UUID> result = identityUtils.getMerchantId(jwt);

            assertTrue(result.isPresent());
            assertEquals(expectedId, result.get());
        }

        @Test
        @DisplayName("getPermissions falls back to gcip nested permissions")
        void getPermissionsFallsBackToGcipNested() {
            when(jwt.getClaim(CLAIM_PERMISSIONS)).thenReturn(null);
            Map<String, Object> attrs = new LinkedHashMap<>();
            attrs.put("permissions", List.of("merchants:read", "payments:read"));
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            when(jwt.getClaim("gcip")).thenReturn(gcip);

            List<String> result = identityUtils.getPermissions(jwt);

            assertEquals(2, result.size());
            assertTrue(result.contains("merchants:read"));
            assertTrue(result.contains("payments:read"));
        }

        @Test
        @DisplayName("getIntegratorId returns empty when gcip nested value is invalid UUID")
        void getIntegratorIdReturnsEmptyWhenGcipNestedIsInvalidUuid() {
            when(jwt.getClaim(CLAIM_INTEGRATOR_ID)).thenReturn(null);
            Map<String, Object> attrs = Map.of("integrator_id", "not-a-uuid");
            Map<String, Object> firebase = Map.of("sign_in_attributes", attrs);
            Map<String, Object> gcip = Map.of("firebase", firebase);
            when(jwt.getClaim("gcip")).thenReturn(gcip);

            Optional<UUID> result = identityUtils.getIntegratorId(jwt);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("getCallerType")
    class GetCallerTypeTests {

        @Test
        @DisplayName("should return INTERNAL_USER when email ends with @latticepay.io")
        void shouldReturnInternalUserWhenEmailEndsWithLatticepayIo() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@latticepay.io");

            assertEquals(CallerType.INTERNAL_USER, identityUtils.getCallerType(jwt));
        }

        @Test
        @DisplayName("should return EXTERNAL_USER when email does not end with @latticepay.io")
        void shouldReturnExternalUserWhenEmailDoesNotEndWithLatticepayIo() {
            when(jwt.getClaim(CLAIM_EMAIL)).thenReturn("user@external.com");

            assertEquals(CallerType.EXTERNAL_USER, identityUtils.getCallerType(jwt));
        }

        @Test
        @DisplayName("should return EXTERNAL_USER when jwt is null")
        void shouldReturnExternalUserWhenJwtIsNull() {
            assertEquals(CallerType.EXTERNAL_USER, identityUtils.getCallerType(null));
        }
    }

    @Nested
    @DisplayName("isWifToken")
    class IsWifTokenTests {

        @Test
        @DisplayName("should return true when issuer is sts.googleapis.com")
        void shouldReturnTrueWhenIssuerIsSts() {
            when(jwt.getIssuer()).thenReturn("https://sts.googleapis.com");

            assertTrue(identityUtils.isWifToken(jwt));
        }

        @Test
        @DisplayName("should return false when issuer is different")
        void shouldReturnFalseWhenIssuerIsDifferent() {
            when(jwt.getIssuer()).thenReturn("https://securetoken.google.com/my-project");

            assertFalse(identityUtils.isWifToken(jwt));
        }

        @Test
        @DisplayName("should return false when issuer is null")
        void shouldReturnFalseWhenIssuerIsNull() {
            when(jwt.getIssuer()).thenReturn(null);

            assertFalse(identityUtils.isWifToken(jwt));
        }

        @Test
        @DisplayName("should return false when jwt is null")
        void shouldReturnFalseWhenJwtIsNullForWifToken() {
            assertFalse(identityUtils.isWifToken(null));
        }
    }

    @Nested
    @DisplayName("getWifProviderIdFromAudience")
    class GetWifProviderIdFromAudienceTests {

        @Test
        @DisplayName("should extract provider ID from valid audience URI")
        void shouldExtractProviderIdFromValidAudience() {
            when(jwt.getAudience()).thenReturn(Set.of(
                    "//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/provider-integrator-int_abc123"));

            Optional<String> result = identityUtils.getWifProviderIdFromAudience(jwt);

            assertTrue(result.isPresent());
            assertEquals(WIF_PROVIDER_ID_SAMPLE, result.get());
        }

        @Test
        @DisplayName("should return empty when audience is null")
        void shouldReturnEmptyWhenAudienceIsNull() {
            when(jwt.getAudience()).thenReturn(null);

            Optional<String> result = identityUtils.getWifProviderIdFromAudience(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when audience is empty set")
        void shouldReturnEmptyWhenAudienceIsEmptySet() {
            when(jwt.getAudience()).thenReturn(Set.of());

            Optional<String> result = identityUtils.getWifProviderIdFromAudience(jwt);

            assertTrue(result.isEmpty());
        }

        @ParameterizedTest(name = "should return empty when audience {0}")
        @CsvSource({
                "ends with slash, '//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/'",
                "has no slash, 'no-slash-audience'",
                "is blank, '   '"
        })
        @DisplayName("should return empty for invalid audience formats")
        void shouldReturnEmptyForInvalidAudience(String description, String audience) {
            when(jwt.getAudience()).thenReturn(Set.of(audience));

            Optional<String> result = identityUtils.getWifProviderIdFromAudience(jwt);

            assertTrue(result.isEmpty());
        }

        @Test
        @DisplayName("should return empty when jwt is null")
        void shouldReturnEmptyWhenJwtIsNullForWifProvider() {
            Optional<String> result = identityUtils.getWifProviderIdFromAudience(null);

            assertTrue(result.isEmpty());
        }
    }

    @Nested
    @DisplayName("extractIntegratorIdFromProvider")
    class ExtractIntegratorIdFromProviderTests {

        @Test
        @DisplayName("should extract integrator ID when provider matches prefix")
        void shouldExtractIntegratorIdWhenProviderMatchesPrefix() {
            Optional<String> result = identityUtils.extractIntegratorIdFromProvider(
                    WIF_PROVIDER_ID_SAMPLE, WIF_PROVIDER_PREFIX);

            assertTrue(result.isPresent());
            assertEquals("int_abc123", result.get());
        }

        @ParameterizedTest(name = "should return empty when {0}")
        @MethodSource("emptyExtractIntegratorIdFromProviderCases")
        @DisplayName("should return empty for invalid provider/prefix")
        void shouldReturnEmptyForExtractIntegratorIdFromProvider(String description, String provider, String prefix) {
            Optional<String> result = identityUtils.extractIntegratorIdFromProvider(provider, prefix);
            assertTrue(result.isEmpty());
        }

        static Stream<Arguments> emptyExtractIntegratorIdFromProviderCases() {
            return Stream.of(
                    Arguments.of("provider does not match prefix", "other-prefix-int_abc123", IdentityUtilsTest.WIF_PROVIDER_PREFIX),
                    Arguments.of("provider ID is null", null, IdentityUtilsTest.WIF_PROVIDER_PREFIX),
                    Arguments.of("prefix is null", IdentityUtilsTest.WIF_PROVIDER_ID_SAMPLE, null),
                    Arguments.of("stripping prefix leaves blank", IdentityUtilsTest.WIF_PROVIDER_PREFIX, IdentityUtilsTest.WIF_PROVIDER_PREFIX),
                    Arguments.of("stripping prefix leaves whitespace only", "provider-integrator-   ", IdentityUtilsTest.WIF_PROVIDER_PREFIX)
            );
        }
    }
}
