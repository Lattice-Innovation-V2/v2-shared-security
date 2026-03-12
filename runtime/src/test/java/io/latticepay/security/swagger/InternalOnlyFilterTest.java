package io.latticepay.security.swagger;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.latticepay.security.identity.IdentityUtils;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for {@link InternalOnlyFilter}.
 * Uses JUnit 6 (Jupiter API) and Mockito per Quarkus 3.31.2 testing stack.
 */
@DisplayName("InternalOnlyFilter")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class InternalOnlyFilterTest {

    @Mock
    private Instance<LatticeSecurityConfig> mockConfigInstance;

    @Mock
    private LatticeSecurityConfig mockConfig;

    @Mock
    private LatticeSecurityConfig.SwaggerProtection mockSwaggerProtection;

    @Mock
    private IdentityUtils mockIdentityUtils;

    @Mock
    private Instance<JsonWebToken> mockJwtInstance;

    @Mock
    private JsonWebToken mockJwt;

    @Mock
    private ContainerRequestContext mockRequestContext;

    @Mock
    private UriInfo mockUriInfo;

    private InternalOnlyFilter filter;

    @BeforeEach
    void setUp() {
        when(mockConfigInstance.isResolvable()).thenReturn(true);
        when(mockConfigInstance.get()).thenReturn(mockConfig);
        when(mockJwtInstance.isResolvable()).thenReturn(true);
        when(mockJwtInstance.get()).thenReturn(mockJwt);
        when(mockConfig.swaggerProtection()).thenReturn(mockSwaggerProtection);
        when(mockSwaggerProtection.enabled()).thenReturn(true);
        when(mockRequestContext.getUriInfo()).thenReturn(mockUriInfo);

        filter = new InternalOnlyFilter(mockConfigInstance, mockJwtInstance, mockIdentityUtils);
    }

    @Nested
    @DisplayName("Internal User Access")
    class InternalUserAccessTests {

        @ParameterizedTest(name = "should allow internal user for path: {0}")
        @CsvSource({
                "/v1/integrators/q/docs",
                "/v1/integrators/q/openapi",
                "/v1/integrators/q/docs/index.html",
                "/v1/integrators/q/openapi/schema.json",
                "/q/docs"
        })
        void shouldAllowInternalUser_forPath(String path) {
            when(mockUriInfo.getPath()).thenReturn(path);
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(true);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("admin@latticepay.io");

            filter.filter(mockRequestContext);

            verify(mockRequestContext, never()).abortWith(org.mockito.ArgumentMatchers.any());
        }
    }

    @Nested
    @DisplayName("External User Access")
    class ExternalUserAccessTests {

        @Test
        @DisplayName("should block external user from accessing /q/docs")
        void shouldBlockExternalUser_fromAccessingDocs() {
            when(mockUriInfo.getPath()).thenReturn("/v1/integrators/q/docs");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("user@external.com");

            filter.filter(mockRequestContext);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(mockRequestContext).abortWith(responseCaptor.capture());
            Response response = responseCaptor.getValue();
            assertAll(
                    () -> assertEquals(403, response.getStatus()),
                    () -> assertEquals("Access to documentation is restricted to internal users", response.getEntity())
            );
        }

        @Test
        @DisplayName("should block external user from accessing /q/openapi")
        void shouldBlockExternalUser_fromAccessingOpenapi() {
            when(mockUriInfo.getPath()).thenReturn("/v1/integrators/q/openapi");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("user@external.com");

            filter.filter(mockRequestContext);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(mockRequestContext).abortWith(responseCaptor.capture());
            Response response = responseCaptor.getValue();
            assertEquals(403, response.getStatus());
        }

        @Test
        @DisplayName("should block external user from accessing /q/docs subpath")
        void shouldBlockExternalUser_fromAccessingDocsSubpath() {
            when(mockUriInfo.getPath()).thenReturn("/v1/integrators/q/docs/index.html");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("user@external.com");

            filter.filter(mockRequestContext);

            verify(mockRequestContext).abortWith(org.mockito.ArgumentMatchers.any());
        }

        @Test
        @DisplayName("should log email when external user is blocked")
        void shouldLogEmail_whenExternalUserBlocked() {
            when(mockUriInfo.getPath()).thenReturn("/q/docs");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("blocked@external.com");

            filter.filter(mockRequestContext);

            verify(mockRequestContext).abortWith(org.mockito.ArgumentMatchers.any());
        }

        @Test
        @DisplayName("should handle null email when external user is blocked")
        void shouldHandleNullEmail_whenExternalUserBlocked() {
            when(mockUriInfo.getPath()).thenReturn("/q/docs");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn(null);

            filter.filter(mockRequestContext);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(mockRequestContext).abortWith(responseCaptor.capture());
            Response response = responseCaptor.getValue();
            assertEquals(403, response.getStatus());
        }
    }

    @Nested
    @DisplayName("Non-Protected Path Access")
    class NonProtectedPathAccessTests {

        @ParameterizedTest(name = "should allow any user for non-protected path: {0}")
        @CsvSource({
                "/v1/integrators",
                "/v1/integrators/q/health",
                "/v1/integrators/q/metrics",
                "/v1/integrators/documents"
        })
        void shouldAllowAnyUser_forNonProtectedPath(String path) {
            when(mockUriInfo.getPath()).thenReturn(path);
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);

            filter.filter(mockRequestContext);

            verify(mockRequestContext, never()).abortWith(org.mockito.ArgumentMatchers.any());
            verify(mockIdentityUtils, never()).isInternalUser(mockJwt);
        }
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("should abort with 503 when LatticeSecurityConfig is not resolvable (fail-closed)")
        void shouldAbortWith503_whenConfigNotResolvable() {
            when(mockConfigInstance.isResolvable()).thenReturn(false);
            when(mockUriInfo.getPath()).thenReturn("/v1/integrators/q/docs");

            filter.filter(mockRequestContext);

            ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
            verify(mockRequestContext).abortWith(responseCaptor.capture());
            Response response = responseCaptor.getValue();
            assertAll(
                    () -> assertEquals(503, response.getStatus()),
                    () -> assertEquals("Security configuration unavailable", response.getEntity())
            );
            verify(mockConfigInstance, never()).get();
        }

        @Test
        @DisplayName("should allow all requests when protection is disabled")
        void shouldAllowAllRequests_whenProtectionDisabled() {
            when(mockSwaggerProtection.enabled()).thenReturn(false);
            when(mockUriInfo.getPath()).thenReturn("/v1/integrators/q/docs");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);

            filter.filter(mockRequestContext);

            verify(mockRequestContext, never()).abortWith(org.mockito.ArgumentMatchers.any());
            verify(mockIdentityUtils, never()).isInternalUser(mockJwt);
        }

        @Test
        @DisplayName("should allow external user when protection is disabled")
        void shouldAllowExternalUser_whenProtectionDisabled() {
            when(mockSwaggerProtection.enabled()).thenReturn(false);
            when(mockUriInfo.getPath()).thenReturn("/q/openapi");
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);
            when(mockIdentityUtils.getEmail(mockJwt)).thenReturn("external@example.com");

            filter.filter(mockRequestContext);

            verify(mockRequestContext, never()).abortWith(org.mockito.ArgumentMatchers.any());
        }
    }

    @Nested
    @DisplayName("Path Matching Tests")
    class PathMatchingTests {

        @ParameterizedTest(name = "should match protected path and block external user: {0}")
        @CsvSource({
                "/v1/service/q/docs",
                "/v1/service/q/docs/swagger-ui.css",
                "/v1/service/q/openapi",
                "/q/openapi/schema.yaml"
        })
        void shouldMatchProtectedPath_andBlockExternalUser(String path) {
            when(mockUriInfo.getPath()).thenReturn(path);
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);

            filter.filter(mockRequestContext);

            verify(mockRequestContext).abortWith(org.mockito.ArgumentMatchers.any());
        }

        @ParameterizedTest(name = "should not match path in different context: {0}")
        @CsvSource({
                "/v1/integrators/docs",
                "/v1/integrators/openapi"
        })
        void shouldNotMatchPath_inDifferentContext(String path) {
            when(mockUriInfo.getPath()).thenReturn(path);
            when(mockIdentityUtils.isInternalUser(mockJwt)).thenReturn(false);

            filter.filter(mockRequestContext);

            verify(mockRequestContext, never()).abortWith(org.mockito.ArgumentMatchers.any());
        }
    }
}
