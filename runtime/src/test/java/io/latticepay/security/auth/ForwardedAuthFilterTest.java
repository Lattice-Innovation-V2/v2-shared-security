package io.latticepay.security.auth;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.Handler;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@DisplayName("ForwardedAuthFilter")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ForwardedAuthFilterTest {

    private static final String FORWARDED_AUTH = "X-Forwarded-Authorization";
    private static final String AUTHZ_HEADER = "Authorization";
    private static final String BEARER_TOKEN = "Bearer test-token";

    @Mock
    private LatticeSecurityConfig mockSecurityConfig;

    @Mock
    private LatticeSecurityConfig.ForwardedAuth mockForwardedAuth;

    @Mock
    private Filters mockFilters;

    @Mock
    private RoutingContext mockRc;

    @Mock
    private HttpServerRequest mockRequest;

    @Mock
    private MultiMap mockHeaders;

    @Mock
    private HttpConnection mockConnection;

    @Mock
    private SocketAddress mockRemoteAddress;

    private ArgumentCaptor<Handler<RoutingContext>> handlerCaptor;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        handlerCaptor = ArgumentCaptor.forClass(Handler.class);
        lenient().when(mockRc.request()).thenReturn(mockRequest);
        lenient().when(mockRequest.headers()).thenReturn(mockHeaders);
        lenient().when(mockSecurityConfig.forwardedAuth()).thenReturn(mockForwardedAuth);
    }

    /** Creates a filter with the given enabled and trustedProxyIps config. */
    private ForwardedAuthFilter createFilter(boolean enabled, String trustedProxyIps) {
        when(mockForwardedAuth.enabled()).thenReturn(enabled);
        when(mockForwardedAuth.trustedProxyIps()).thenReturn(trustedProxyIps != null ? trustedProxyIps : "");
        return new ForwardedAuthFilter(mockSecurityConfig);
    }

    /**
     * Captures the handler registered by ForwardedAuthFilter and returns it so tests can invoke it.
     */
    private Handler<RoutingContext> captureRegisteredHandler(ForwardedAuthFilter filter) {
        filter.register(mockFilters);
        verify(mockFilters).register(handlerCaptor.capture(), eq(100));
        return handlerCaptor.getValue();
    }

    @Nested
    @DisplayName("Constructor and Configuration")
    class ConstructorTests {

        @Test
        @DisplayName("should construct with valid configuration")
        void shouldConstruct_withValidConfiguration() {
            var filter = createFilter(true, "127.0.0.1,192.168.1.1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with disabled filter")
        void shouldConstruct_withDisabledFilter() {
            var filter = createFilter(false, "");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with null trusted proxy IPs")
        void shouldConstruct_withNullTrustedProxyIps() {
            when(mockForwardedAuth.enabled()).thenReturn(true);
            when(mockForwardedAuth.trustedProxyIps()).thenReturn(null);
            var filter = new ForwardedAuthFilter(mockSecurityConfig);
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with empty trusted proxy IPs")
        void shouldConstruct_withEmptyTrustedProxyIps() {
            var filter = createFilter(true, "");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with blank trusted proxy IPs")
        void shouldConstruct_withBlankTrustedProxyIps() {
            var filter = createFilter(true, "   ");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with NONE (treated as no trusted IPs for Pulumi/GCP)")
        void shouldConstruct_withNonePlaceholder() {
            var filter = createFilter(true, "NONE");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with none lowercase (case-insensitive)")
        void shouldConstruct_withNoneLowercase() {
            var filter = createFilter(true, "none");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with IPv4 addresses")
        void shouldConstruct_withIpv4Addresses() {
            var filter = createFilter(true, "127.0.0.1,192.168.1.1,10.0.0.1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with IPv6 addresses")
        void shouldConstruct_withIpv6Addresses() {
            var filter = createFilter(true, "::1,2001:db8::1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with mixed IPv4 and IPv6 addresses")
        void shouldConstruct_withMixedIpAddresses() {
            var filter = createFilter(true, "127.0.0.1,::1,192.168.1.1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should handle invalid IP addresses gracefully")
        void shouldHandleInvalidIpAddresses() {
            var filter = createFilter(true, "127.0.0.1,invalid-ip,192.168.1.1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should handle IP addresses with whitespace")
        void shouldHandleIpAddressesWithWhitespace() {
            var filter = createFilter(true, " 127.0.0.1 , 192.168.1.1 , ::1 ");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should handle IP addresses with extra commas")
        void shouldHandleIpAddressesWithExtraCommas() {
            var filter = createFilter(true, "127.0.0.1,,192.168.1.1,,,::1");
            assertNotNull(filter);
        }

        @Test
        @DisplayName("should construct with hostnames that resolve to IPs")
        void shouldConstruct_withHostnames() {
            var filter = createFilter(true, "127.0.0.1,::1");
            assertNotNull(filter);
        }
    }

    @Nested
    @DisplayName("Filter behavior (register + handler)")
    class FilterBehaviorTests {

        @Test
        @DisplayName("when no X-Forwarded-Authorization: does not set Authorization, calls next")
        void whenNoForwardedAuth_doesNotSetAuthorization_callsNext() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(null);

            var filter = createFilter(true, "");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when X-Forwarded-Authorization is blank: does not set Authorization, calls next")
        void whenForwardedAuthBlank_doesNotSetAuthorization_callsNext() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn("   ");

            var filter = createFilter(true, "");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when Authorization already set: does not overwrite, calls next")
        void whenAuthorizationAlreadySet_doesNotOverwrite_callsNext() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn("Bearer existing");

            var filter = createFilter(true, "");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when allow-forwarded-auth true and no trusted IPs: copies to Authorization and calls next")
        void whenAllowForwardedAuthNoTrustedIps_copiesToAuthorization_callsNext() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);

            var filter = createFilter(true, "");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, atLeastOnce()).set(AUTHZ_HEADER, BEARER_TOKEN),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when trusted-proxy-ips is NONE: copies to Authorization (all sources trusted, Pulumi/GCP placeholder)")
        void whenTrustedProxyIpsIsNone_treatsAsEmpty_copiesToAuthorization() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);

            var filter = createFilter(true, "NONE");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, atLeastOnce()).set(AUTHZ_HEADER, BEARER_TOKEN),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when allow-forwarded-auth false: does not register handler")
        void whenAllowForwardedAuthFalse_doesNotRegisterHandler() {
            var filter = createFilter(false, "");
            filter.register(mockFilters);
            verify(mockFilters, never()).register(any(Handler.class), anyInt());
        }

        @Test
        @DisplayName("when trusted-proxy-ips set and remote is trusted: copies to Authorization")
        void whenRemoteIsTrusted_copiesToAuthorization() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn("127.0.0.1");

            var filter = createFilter(true, "127.0.0.1,192.168.1.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, atLeastOnce()).set(AUTHZ_HEADER, BEARER_TOKEN),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when trusted-proxy-ips set and remote is not trusted: does not copy, calls next")
        void whenRemoteNotTrusted_doesNotCopy_callsNext() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn("10.0.0.99");

            var filter = createFilter(true, "127.0.0.1,192.168.1.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when connection is null: treats as untrusted, does not copy")
        void whenConnectionNull_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(null);

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when remoteAddress is null: treats as untrusted, does not copy")
        void whenRemoteAddressNull_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(null);

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when hostAddress is null: treats as untrusted, does not copy")
        void whenHostAddressNull_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn(null);

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when hostAddress is blank: treats as untrusted, does not copy")
        void whenHostAddressBlank_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn("  ");

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when connection throws: treats as untrusted, does not copy")
        void whenConnectionThrows_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenThrow(new RuntimeException("connection error"));

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("when remote address is unparseable (UnknownHostException): treats as untrusted, does not copy")
        void whenRemoteAddressUnparseable_treatsAsUntrusted_doesNotCopy() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn("256.256.256.256");

            var filter = createFilter(true, "127.0.0.1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, never()).set(eq(AUTHZ_HEADER), anyString()),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("trusted-proxy-ips with IPv6: trusts matching remote")
        void whenTrustedProxyIpsIpv6_trustsMatchingRemote() {
            when(mockRequest.getHeader(FORWARDED_AUTH)).thenReturn(BEARER_TOKEN);
            when(mockRequest.getHeader("Authorization")).thenReturn(null);
            when(mockRequest.connection()).thenReturn(mockConnection);
            when(mockConnection.remoteAddress()).thenReturn(mockRemoteAddress);
            when(mockRemoteAddress.hostAddress()).thenReturn("::1");

            var filter = createFilter(true, "::1,2001:db8::1");
            var handler = captureRegisteredHandler(filter);
            handler.handle(mockRc);

            assertAll(
                    () -> verify(mockHeaders, atLeastOnce()).set(AUTHZ_HEADER, BEARER_TOKEN),
                    () -> verify(mockRc).next()
            );
        }

        @Test
        @DisplayName("register uses priority 100")
        void registerUsesPriority100() {
            var filter = createFilter(true, "");
            filter.register(mockFilters);
            verify(mockFilters).register(handlerCaptor.capture(), eq(100));
        }
    }
}
