package io.latticepay.security.auth;

import io.latticepay.security.config.ActiveProfileSupplier;
import io.latticepay.security.config.GcipConstants;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.inject.Instance;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link HybridTenantConfigResolver}. Uses JUnit Jupiter API (JUnit 5/6 compatible).
 */
@DisplayName("HybridTenantConfigResolver")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HybridTenantConfigResolverTest {

    private static final String VALID_GCIP_PROJECT_ID = "test-project-id";
    private static final String VALID_IAP_CLIENT_ID = "test-client-id.apps.googleusercontent.com";
    private static final String IAP_HEADER = "x-goog-iap-jwt-assertion";
    private static final String FORWARDED_IAP_HEADER = "X-Forwarded-IAP-JWT";
    private static final String FORWARDED_AUTH_HEADER = "X-Forwarded-Authorization";
    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Mock
    private LatticeSecurityConfig mockConfig;

    @Mock
    private LatticeSecurityConfig.Iap mockIap;

    @Mock
    private LatticeSecurityConfig.Gcip mockGcip;

    @Mock
    private LatticeSecurityConfig.Dev mockDev;

    @Mock
    private LatticeSecurityConfig.Wif mockWif;

    @Mock
    private ActiveProfileSupplier mockActiveProfileSupplier;

    @Mock
    private Instance<ActiveProfileSupplier> mockActiveProfileSupplierInstance;

    private RoutingContext routingContext;
    private HttpServerRequest httpServerRequest;
    private OidcRequestContext<OidcTenantConfig> requestContext;

    @BeforeEach
    void setUp() {
        routingContext = mock(RoutingContext.class);
        httpServerRequest = mock(HttpServerRequest.class);
        requestContext = mock(OidcRequestContext.class);
        when(routingContext.request()).thenReturn(httpServerRequest);
        lenient().when(mockConfig.iap()).thenReturn(mockIap);
        lenient().when(mockConfig.gcip()).thenReturn(mockGcip);
        lenient().when(mockConfig.dev()).thenReturn(mockDev);
        lenient().when(mockConfig.wif()).thenReturn(mockWif);
        lenient().when(mockIap.enabled()).thenReturn(true);
        lenient().when(mockIap.additionalAudiences()).thenReturn(Optional.empty());
        lenient().when(mockGcip.enabled()).thenReturn(true);
        lenient().when(mockDev.enabled()).thenReturn(false);
        lenient().when(mockWif.enabled()).thenReturn(false);
        lenient().when(mockWif.jwksUrl()).thenReturn(Optional.empty());
        lenient().when(mockActiveProfileSupplier.getActiveProfile()).thenReturn("test");
        lenient().when(mockActiveProfileSupplierInstance.isUnsatisfied()).thenReturn(false);
        lenient().when(mockActiveProfileSupplierInstance.isResolvable()).thenReturn(true);
        lenient().when(mockActiveProfileSupplierInstance.get()).thenReturn(mockActiveProfileSupplier);
    }

    /** Creates a resolver with the given GCIP project ID and IAP client ID. */
    private HybridTenantConfigResolver createResolver(String gcipProjectId, String iapClientId) {
        when(mockIap.clientId()).thenReturn(Optional.ofNullable(iapClientId));
        when(mockGcip.projectId()).thenReturn(Optional.ofNullable(gcipProjectId));
        return new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
    }

    /** Resolves tenant config and blocks; single invocation for assertThrows. */
    private OidcTenantConfig resolveIndefinitely(HybridTenantConfigResolver resolver) {
        return resolver.resolve(routingContext, requestContext).await().indefinitely();
    }

    @Nested
    @DisplayName("Tenant Selection")
    class TenantSelectionTests {

        @Test
        @DisplayName("should select IAP tenant when x-goog-iap-jwt-assertion header present")
        void shouldSelectIapTenant_whenIapHeaderPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select forwarded IAP tenant when X-Forwarded-IAP-JWT header present")
        void shouldSelectForwardedIapTenant_whenForwardedIapHeaderPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap-forwarded", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should prefer direct IAP over forwarded IAP when both headers present")
        void shouldPreferDirectIap_whenBothIapHeadersPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("direct-iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should prefer forwarded IAP over GCIP when both headers present")
        void shouldPreferForwardedIap_overGcip() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap-forwarded", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should handle blank forwarded IAP header as not present")
        void shouldHandleBlankForwardedIapHeader() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("   ");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should handle empty string forwarded IAP header as not present")
        void shouldHandleEmptyForwardedIapHeader() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP tenant when Authorization Bearer token present")
        void shouldSelectGcipTenant_whenAuthorizationBearerPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP tenant when X-Forwarded-Authorization header present")
        void shouldSelectGcipTenant_whenForwardedAuthPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn("Bearer forwarded-token");
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        static Stream<Arguments> nullTenantHeaderCombinations() {
            return Stream.of(
                    Arguments.of(null, null, null),
                    Arguments.of(null, null, "Basic dXNlcjpwYXNz"),
                    Arguments.of(null, "   ", null),
                    Arguments.of(null, "", null),
                    Arguments.of(null, null, "Bearer")
            );
        }

        @ParameterizedTest(name = "should return null when iap={0}, forwarded={1}, auth={2}")
        @MethodSource("nullTenantHeaderCombinations")
        @DisplayName("should return null for header combinations that yield no tenant")
        void shouldReturnNull_forVariousHeaderCombinations(String iapHeader, String forwardedAuth, String authHeader) {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(iapHeader);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(forwardedAuth);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(authHeader);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNull(config);
        }

        @Test
        @DisplayName("should prefer IAP tenant when both IAP and GCIP headers present")
        void shouldPreferIapTenant_whenBothHeadersPresent() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn("Bearer gcip-token");
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should handle blank IAP header as not present")
        void shouldHandleBlankIapHeader() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("   ");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should handle empty string IAP header as not present")
        void shouldHandleEmptyIapHeader() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP when Authorization is Bearer with trailing space and token")
        void shouldSelectGcip_whenBearerWithTrailingSpace() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer token ");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP when Authorization uses uppercase BEARER scheme (RFC-compliant)")
        void shouldSelectGcip_whenBearerSchemeUppercase() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("BEARER gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP when Authorization has multiple spaces between scheme and token (RFC-compliant)")
        void shouldSelectGcip_whenBearerHasMultipleSpaces() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer   \t  gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should return null when Authorization is Basic (not Bearer)")
        void shouldReturnNull_whenAuthorizationIsBasic() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Basic dXNlcjpwYXNz");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNull(config);
        }

    }

    @Nested
    @DisplayName("IAP Configuration")
    class IapConfigurationTests {

        @Test
        @DisplayName("should build IAP config with correct properties")
        void shouldBuildIapConfig_withCorrectProperties() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("iap", config.tenantId().orElse(null)),
                    () -> assertEquals(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE,
                            config.applicationType().orElse(null)),
                    () -> assertEquals("https://www.gstatic.com/iap/verify/public_key-jwk", config.jwksPath().orElse(null)),
                    () -> assertEquals("https://cloud.google.com/iap", config.token().issuer().orElse(null)),
                    () -> assertEquals(VALID_IAP_CLIENT_ID, config.token().audience().orElse(null).getFirst()),
                    () -> assertEquals(IAP_HEADER, config.token().header().orElse(null)),
                    () -> assertEquals(io.quarkus.oidc.runtime.OidcTenantConfig.SignatureAlgorithm.ES256,
                            config.token().signatureAlgorithm().orElse(null))
            );
        }

        @Test
        @DisplayName("should cache IAP config and return same instance")
        void shouldCacheIapConfig() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);

            OidcTenantConfig config1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig config2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(config1, config2);
        }

        private static final String IAP_CLIENT_ID_REQUIRED_MESSAGE =
                "latticepay.security.iap.client-id is required for IAP tenant but is missing or blank. "
                        + "Set latticepay.security.iap.client-id (or IAP_CLIENT_ID) to the OAuth2 client ID of your IAP-protected resource so only tokens issued for that audience are accepted.";

        static Stream<Arguments> invalidIapClientIds() {
            return Stream.of(
                    Arguments.of((String) null),
                    Arguments.of(""),
                    Arguments.of("   ")
            );
        }

        @ParameterizedTest(name = "should throw when IAP client ID is ''{0}''")
        @MethodSource("invalidIapClientIds")
        @DisplayName("should throw exception when IAP client ID is null, empty, or blank")
        void shouldThrowException_whenIapClientIdInvalid(String iapClientId) {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, iapClientId);

            var exception = assertThrows(IllegalStateException.class, () -> resolveIndefinitely(resolver));

            assertEquals(IAP_CLIENT_ID_REQUIRED_MESSAGE, exception.getMessage());
        }

        @Test
        @DisplayName("should use trimmed IAP client ID in config when constructor receives whitespace")
        void shouldUseTrimmedIapClientId_whenConstructorReceivesWhitespace() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");

            when(mockIap.clientId()).thenReturn(Optional.of("  trimmed-client-id  "));
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));
            var resolver = new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("iap", config.tenantId().orElse(null)),
                    () -> assertEquals("  trimmed-client-id  ", config.token().audience().orElse(null).getFirst())
            );
        }

        @Test
        @DisplayName("should include additional audiences in IAP config when configured")
        void shouldIncludeAdditionalAudiences_whenConfigured() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockIap.additionalAudiences()).thenReturn(Optional.of("/projects/123/backendServices/456,/projects/123/backendServices/789"));
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));
            var resolver = new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            List<String> audiences = config.token().audience().orElse(null);
            assertNotNull(audiences);
            assertEquals(3, audiences.size());
            assertEquals(VALID_IAP_CLIENT_ID, audiences.get(0));
            assertEquals("/projects/123/backendServices/456", audiences.get(1));
            assertEquals("/projects/123/backendServices/789", audiences.get(2));
        }

        @Test
        @DisplayName("should build IAP config with only clientId when additional audiences empty")
        void shouldBuildIapConfig_withOnlyClientId_whenAdditionalAudiencesEmpty() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockIap.additionalAudiences()).thenReturn(Optional.empty());
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));
            var resolver = new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            List<String> audiences = config.token().audience().orElse(null);
            assertNotNull(audiences);
            assertEquals(1, audiences.size());
            assertEquals(VALID_IAP_CLIENT_ID, audiences.getFirst());
        }
    }

    @Nested
    @DisplayName("Forwarded IAP Configuration")
    class ForwardedIapConfigurationTests {

        @Test
        @DisplayName("should build forwarded IAP config with correct properties")
        void shouldBuildForwardedIapConfig_withCorrectProperties() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("iap-forwarded", config.tenantId().orElse(null)),
                    () -> assertEquals(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE,
                            config.applicationType().orElse(null)),
                    () -> assertEquals("https://www.gstatic.com/iap/verify/public_key-jwk", config.jwksPath().orElse(null)),
                    () -> assertEquals("https://cloud.google.com/iap", config.token().issuer().orElse(null)),
                    () -> assertEquals(VALID_IAP_CLIENT_ID, config.token().audience().orElse(null).getFirst()),
                    () -> assertEquals(FORWARDED_IAP_HEADER, config.token().header().orElse(null)),
                    () -> assertEquals(io.quarkus.oidc.runtime.OidcTenantConfig.SignatureAlgorithm.ES256,
                            config.token().signatureAlgorithm().orElse(null))
            );
        }

        @Test
        @DisplayName("should cache forwarded IAP config and return same instance")
        void shouldCacheForwardedIapConfig() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);

            OidcTenantConfig config1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig config2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(config1, config2);
        }

        @Test
        @DisplayName("should include additional audiences in forwarded IAP config when configured")
        void shouldIncludeAdditionalAudiences_inForwardedIapConfig() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");
            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockIap.additionalAudiences()).thenReturn(Optional.of("/projects/123/backendServices/456,/projects/123/backendServices/789"));
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));
            var resolver = new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            List<String> audiences = config.token().audience().orElse(null);
            assertNotNull(audiences);
            assertEquals(3, audiences.size());
            assertEquals(VALID_IAP_CLIENT_ID, audiences.get(0));
            assertEquals("/projects/123/backendServices/456", audiences.get(1));
            assertEquals("/projects/123/backendServices/789", audiences.get(2));
        }

        @Test
        @DisplayName("should cache direct IAP and forwarded IAP configs independently")
        void shouldCacheDirectAndForwardedIapIndependently() {
            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);

            // First resolve with direct IAP
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("direct-iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn(null);
            OidcTenantConfig directConfig = resolver.resolve(routingContext, requestContext).await().indefinitely();

            // Then resolve with forwarded IAP
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_IAP_HEADER)).thenReturn("forwarded-iap-jwt-token");
            OidcTenantConfig forwardedConfig = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(directConfig);
            assertNotNull(forwardedConfig);
            assertEquals("iap", directConfig.tenantId().orElse(null));
            assertEquals("iap-forwarded", forwardedConfig.tenantId().orElse(null));
            assertEquals(IAP_HEADER, directConfig.token().header().orElse(null));
            assertEquals(FORWARDED_IAP_HEADER, forwardedConfig.token().header().orElse(null));
        }
    }

    @Nested
    @DisplayName("GCIP Configuration")
    class GcipConfigurationTests {

        @Test
        @DisplayName("should build GCIP config with correct properties")
        void shouldBuildGcipConfig_withCorrectProperties() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("gcip", config.tenantId().orElse(null)),
                    () -> assertEquals(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE,
                            config.applicationType().orElse(null)),
                    () -> assertEquals("https://securetoken.google.com/" + VALID_GCIP_PROJECT_ID,
                            config.authServerUrl().orElse(null)),
                    () -> assertEquals("https://securetoken.google.com/" + VALID_GCIP_PROJECT_ID,
                            config.token().issuer().orElse(null)),
                    () -> assertEquals(VALID_GCIP_PROJECT_ID, config.token().audience().orElse(null).getFirst())
            );
        }

        @Test
        @DisplayName("should cache GCIP config and return same instance")
        void shouldCacheGcipConfig() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);

            OidcTenantConfig config1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig config2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(config1, config2);
        }

        private static final String GCIP_PROJECT_ID_REQUIRED_MESSAGE =
                "GCIP is enabled but GCP_PROJECT_ID is not set. Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.";

        static Stream<Arguments> invalidGcipProjectIds() {
            return Stream.of(
                    Arguments.of((String) null),
                    Arguments.of(""),
                    Arguments.of("   "),
                    Arguments.of(GcipConstants.MISSING_GCP_PROJECT_ID)
            );
        }

        @ParameterizedTest(name = "should throw when GCIP project ID is ''{0}''")
        @MethodSource("invalidGcipProjectIds")
        @DisplayName("should throw exception when GCIP project ID is null, empty, blank, or missing placeholder")
        void shouldThrowException_whenGcipProjectIdInvalid(String gcipProjectId) {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            var resolver = createResolver(gcipProjectId, VALID_IAP_CLIENT_ID);

            var exception = assertThrows(IllegalStateException.class, () -> resolveIndefinitely(resolver));

            assertEquals(GCIP_PROJECT_ID_REQUIRED_MESSAGE, exception.getMessage());
        }

        @Test
        @DisplayName("should use trimmed GCIP project ID in config when constructor receives whitespace")
        void shouldUseTrimmedGcipProjectId_whenConstructorReceivesWhitespace() {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockGcip.projectId()).thenReturn(Optional.of("  trimmed-project-id  "));
            var resolver = new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("gcip", config.tenantId().orElse(null)),
                    () -> assertEquals("https://securetoken.google.com/  trimmed-project-id  ", config.authServerUrl().orElse(null)),
                    () -> assertEquals("  trimmed-project-id  ", config.token().audience().orElse(null).getFirst())
            );
        }
    }

    @Nested
    @DisplayName("Dev Tenant")
    class DevTenantTests {

        @BeforeEach
        void setDevProfile() {
            when(mockActiveProfileSupplier.getActiveProfile()).thenReturn("dev");
        }

        private static final String DEV_ISSUER = "https://dev.issuer.local";
        private static final String DEV_PUBLIC_KEY_LOCATION = "test-publicKey.pem";
        private static final String DEV_PEM_CONTENT = """
                -----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3k2aOzk+Rz8JI1W2CUb+
                252WEJHFkUuRBpAAm+OA92IVUsjmGFLww1bYdzheQEPpQi1F6LCAxd9oa2Kb7JwG
                LQC7imnRJXfH+fGg70FEE8r301iS/6BqQsnO0FE0EhzutPpvWqItCOAGxNhjzTH5
                ddw+MMhCMiNqryjwrK7Rx1OERYzNKJtA4MkC75iyBa3EcadrzP+JTmZ2R0WpEDJE
                KJr5vVB7GRrp8caGGKgmKLKzGzRRXKRjlxp7NR8P8nrhMONrr8qI2RnblMJW+vuA
                zhd2H+/mDyWYfp+D5ZDxLJ9fCpGFntd2zsJ/aOojYecyZM8QNn9FiXZY/suZeHWE
                IwIDAQAB
                -----END PUBLIC KEY-----
                """;

        @Test
        @DisplayName("when dev enabled and Bearer iss matches and public key from file should select dev tenant")
        void whenDevEnabled_andIssMatches_andPublicKeyFromFile_shouldSelectDevTenant(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(mockDev.audience()).thenReturn("any");
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss(DEV_ISSUER));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("dev", config.tenantId().orElse(null));
            assertEquals(DEV_ISSUER, config.token().issuer().orElse(null));
            assertEquals("any", config.token().audience().orElse(null).getFirst());
        }

        @Test
        @DisplayName("when dev enabled with blank audience should default to any")
        void whenDevEnabled_withBlankAudience_shouldDefaultToAny(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(mockDev.audience()).thenReturn("  ");
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss(DEV_ISSUER));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertEquals("dev", config.tenantId().orElse(null));
            assertEquals("any", config.token().audience().orElse(null).getFirst());
        }

        @Test
        @DisplayName("when dev enabled and Bearer with no token should return null (RFC: empty token is not Bearer)")
        void whenDevEnabled_andBearerWithNoToken_shouldReturnNull(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer ");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNull(config);
        }

        @Test
        @DisplayName("when dev enabled and public-key-location is classpath: only should throw at construction")
        void whenDevEnabled_andPublicKeyLocationClasspathOnly_shouldThrow() {
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of("classpath:"));

            var ex = assertThrows(IllegalStateException.class,
                    () -> createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID));
            assertTrue(ex.getMessage().contains("empty or invalid"));
        }

        @Test
        @DisplayName("when dev disabled and Bearer with dev iss present should select GCIP")
        void whenDevDisabled_andBearerWithDevIss_shouldSelectGcip() {
            when(mockDev.enabled()).thenReturn(false);
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss(DEV_ISSUER));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("when dev enabled and Bearer iss does not match should select GCIP tenant")
        void whenDevEnabled_andIssDifferent_shouldSelectGcip(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss("https://securetoken.google.com/other"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("when dev enabled and Bearer token malformed should select GCIP tenant")
        void whenDevEnabled_andMalformedToken_shouldSelectGcip(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer not.three.parts.or.invalid");

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("when both IAP header and dev Bearer present should prefer IAP tenant")
        void whenIapAndDevBearerPresent_shouldPreferIap(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss(DEV_ISSUER));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("when dev enabled but issuer missing should throw IllegalStateException at construction")
        void whenDevEnabledButIssuerMissing_shouldThrow() {
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(""));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(DEV_PUBLIC_KEY_LOCATION));

            var ex = assertThrows(IllegalStateException.class,
                    () -> createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID));
            assertTrue(ex.getMessage().contains("latticepay.security.dev.issuer"));
        }

        @Test
        @DisplayName("when dev enabled but profile is not dev should throw at construction")
        void whenDevEnabled_andProfileNotDev_shouldThrowAtConstruction() {
            when(mockActiveProfileSupplier.getActiveProfile()).thenReturn("prod");
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.restrictToDevProfile()).thenReturn(true);
            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));

            var ex = assertThrows(IllegalStateException.class,
                    () -> new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance));
            assertTrue(ex.getMessage().contains("only allowed when the Quarkus profile is 'dev'"));
            assertTrue(ex.getMessage().contains("prod"));
        }

        @Test
        @DisplayName("when dev enabled but production build (bean unsatisfied) should throw at construction")
        void whenDevEnabled_andProductionBuild_shouldThrowAtConstruction() {
            when(mockActiveProfileSupplierInstance.isUnsatisfied()).thenReturn(true);
            when(mockDev.enabled()).thenReturn(true);
            when(mockIap.clientId()).thenReturn(Optional.of(VALID_IAP_CLIENT_ID));
            when(mockGcip.projectId()).thenReturn(Optional.of(VALID_GCIP_PROJECT_ID));

            var ex = assertThrows(IllegalStateException.class,
                    () -> new HybridTenantConfigResolver(mockConfig, mockActiveProfileSupplierInstance));
            assertTrue(ex.getMessage().contains("not available in production builds"));
        }

        @Test
        @DisplayName("when dev enabled but public-key-location missing should throw IllegalStateException at construction")
        void whenDevEnabledButPublicKeyLocationMissing_shouldThrow() {
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.empty());

            var ex = assertThrows(IllegalStateException.class,
                    () -> createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID));
            assertTrue(ex.getMessage().contains("latticepay.security.dev.public-key-location"));
        }

        @Test
        @DisplayName("when dev enabled and classpath resource missing should throw at construction")
        void whenDevEnabled_andClasspathResourceMissing_shouldThrow() {
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of("classpath:nonexistent-dev-key.pem"));

            var ex = assertThrows(IllegalStateException.class,
                    () -> createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID));
            assertTrue(ex.getMessage().contains("not found on classpath"));
        }

        @Test
        @DisplayName("when dev enabled and public key file path does not exist should throw at construction")
        void whenDevEnabled_andPublicKeyFileNotFound_shouldThrow(@TempDir Path tempDir) {
            Path absentFile = tempDir.resolve("absent.pem");
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(absentFile.toAbsolutePath().toString()));

            var ex = assertThrows(IllegalStateException.class,
                    () -> createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID));
            assertTrue(ex.getMessage().contains("Failed to read dev tenant public key from file"));
        }

        @Test
        @DisplayName("when dev enabled resolve twice should return same cached dev config")
        void whenDevEnabled_resolveTwice_shouldReturnSameCachedDevConfig(@TempDir Path tempDir) throws Exception {
            Path pemFile = tempDir.resolve("dev-publicKey.pem");
            Files.writeString(pemFile, DEV_PEM_CONTENT);
            when(mockDev.enabled()).thenReturn(true);
            when(mockDev.issuer()).thenReturn(Optional.of(DEV_ISSUER));
            when(mockDev.publicKeyLocation()).thenReturn(Optional.of(pemFile.toAbsolutePath().toString()));
            when(mockDev.audience()).thenReturn("any");
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer " + TestJwtFactory.minimalJwtWithIss(DEV_ISSUER));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig config2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(config1, config2);
            assertEquals("dev", config1.tenantId().orElse(null));
        }
    }

    @Nested
    @DisplayName("WIF Tenant")
    class WifTenantTests {

        private static final String WIF_AUDIENCE =
                "//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/my-provider";

        @Test
        @DisplayName("should select WIF tenant when WIF enabled and Bearer iss is sts.googleapis.com")
        void shouldSelectWifTenant_whenWifEnabledAndIssIsSts() {
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.of(WIF_AUDIENCE));
            when(mockWif.jwksUrl()).thenReturn(Optional.empty());
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("wif", config.tenantId().orElse(null)),
                    () -> assertEquals("https://sts.googleapis.com", config.token().issuer().orElse(null)),
                    () -> assertEquals(WIF_AUDIENCE, config.token().audience().orElse(null).getFirst()),
                    () -> assertEquals(Optional.of(false), config.discoveryEnabled()),
                    () -> assertEquals("https://www.googleapis.com/oauth2/v3/certs", config.jwksPath().orElse(null))
            );
        }

        @Test
        @DisplayName("should use custom JWKS URL when configured")
        void shouldUseCustomJwksUrl_whenConfigured() {
            String customJwks = "https://custom.example.com/jwks";
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.of(WIF_AUDIENCE));
            when(mockWif.jwksUrl()).thenReturn(Optional.of(customJwks));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertAll(
                    () -> assertNotNull(config),
                    () -> assertEquals("wif", config.tenantId().orElse(null)),
                    () -> assertEquals(Optional.of(false), config.discoveryEnabled()),
                    () -> assertEquals(customJwks, config.jwksPath().orElse(null))
            );
        }

        @Test
        @DisplayName("should cache WIF config and return same instance")
        void shouldCacheWifConfig() {
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.of(WIF_AUDIENCE));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig config2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(config1, config2);
            assertEquals("wif", config1.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP tenant when WIF disabled even if iss is sts.googleapis.com")
        void shouldSelectGcip_whenWifDisabled() {
            when(mockWif.enabled()).thenReturn(false);
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should prefer IAP over WIF when both IAP header and WIF Bearer present")
        void shouldPreferIap_overWif() {
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.of(WIF_AUDIENCE));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("iap", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should select GCIP when WIF enabled but Bearer iss is not sts.googleapis.com")
        void shouldSelectGcip_whenWifEnabledButIssDifferent() {
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.of(WIF_AUDIENCE));
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://securetoken.google.com/my-project"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertNotNull(config);
            assertEquals("gcip", config.tenantId().orElse(null));
        }

        @Test
        @DisplayName("should throw when WIF enabled but audience is not configured")
        void shouldThrow_whenWifEnabledButAudienceNotConfigured() {
            when(mockWif.enabled()).thenReturn(true);
            when(mockWif.audience()).thenReturn(Optional.empty());
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(
                    "Bearer " + TestJwtFactory.minimalJwtWithIss("https://sts.googleapis.com"));

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            var ex = assertThrows(IllegalStateException.class, () -> resolveIndefinitely(resolver));

            assertTrue(ex.getMessage().contains("WIF is enabled but audience is not set"));
        }
    }

    @Nested
    @DisplayName("Configuration Caching")
    class ConfigurationCachingTests {

        @Test
        @DisplayName("should cache IAP and GCIP configs independently")
        void shouldCacheConfigsIndependently() {
            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);

            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            OidcTenantConfig iapConfig1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig iapConfig2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");
            OidcTenantConfig gcipConfig1 = resolver.resolve(routingContext, requestContext).await().indefinitely();
            OidcTenantConfig gcipConfig2 = resolver.resolve(routingContext, requestContext).await().indefinitely();

            assertSame(iapConfig1, iapConfig2);
            assertSame(gcipConfig1, gcipConfig2);

            assertNotNull(iapConfig1);
            assertNotNull(gcipConfig1);
            assertEquals("iap", iapConfig1.tenantId().orElse(null));
            assertEquals("gcip", gcipConfig1.tenantId().orElse(null));
        }

        @Test
        @DisplayName("concurrent IAP resolution returns same config and exercises CAS fallback branch")
        void shouldReturnSameIapConfigUnderConcurrentResolution() throws InterruptedException {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn("iap-jwt-token");
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn(null);

            var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
            int threadCount = 20;
            CountDownLatch startLatch = new CountDownLatch(1);
            List<OidcTenantConfig> results = new ArrayList<>();
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            try {
                for (int i = 0; i < threadCount; i++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await(10, TimeUnit.SECONDS);
                            OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();
                            synchronized (results) {
                                results.add(config);
                            }
                        } catch (Exception e) {
                            fail("Thread failed: " + e.getMessage());
                        }
                    });
                }
                startLatch.countDown();
                executor.shutdown();
                if (!executor.awaitTermination(15, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
                assertEquals(threadCount, results.size(), "All threads should complete");
                OidcTenantConfig first = results.getFirst();
                assertNotNull(first);
                assertEquals("iap", first.tenantId().orElse(null));
                for (OidcTenantConfig config : results) {
                    assertSame(first, config, "All concurrent resolutions must return the same cached IAP config");
                }
            } finally {
                executor.shutdownNow();
            }
        }

        @Test
        @DisplayName("concurrent GCIP resolution returns same config and exercises CAS fallback branch")
        void shouldReturnSameGcipConfigUnderConcurrentResolution() throws InterruptedException {
            when(httpServerRequest.getHeader(IAP_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(FORWARDED_AUTH_HEADER)).thenReturn(null);
            when(httpServerRequest.getHeader(AUTHORIZATION_HEADER)).thenReturn("Bearer gcip-token");

            int threadCount = 50;
            for (int round = 0; round < 10; round++) {
                var resolver = createResolver(VALID_GCIP_PROJECT_ID, VALID_IAP_CLIENT_ID);
                CountDownLatch startLatch = new CountDownLatch(1);
                List<OidcTenantConfig> results = new ArrayList<>();
                ExecutorService executor = Executors.newFixedThreadPool(threadCount);

                try {
                    for (int i = 0; i < threadCount; i++) {
                        executor.submit(() -> {
                            try {
                                startLatch.await(10, TimeUnit.SECONDS);
                                OidcTenantConfig config = resolver.resolve(routingContext, requestContext).await().indefinitely();
                                synchronized (results) {
                                    results.add(config);
                                }
                            } catch (Exception e) {
                                fail("Thread failed: " + e.getMessage());
                            }
                        });
                    }
                    startLatch.countDown();
                    executor.shutdown();
                    if (!executor.awaitTermination(15, TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                    }
                    assertEquals(threadCount, results.size(), "All threads should complete in round " + round);
                    OidcTenantConfig first = results.getFirst();
                    assertNotNull(first);
                    assertEquals("gcip", first.tenantId().orElse(null));
                    for (OidcTenantConfig config : results) {
                        assertSame(first, config, "All concurrent resolutions must return the same cached GCIP config");
                    }
                } finally {
                    executor.shutdownNow();
                }
            }
        }
    }
}
