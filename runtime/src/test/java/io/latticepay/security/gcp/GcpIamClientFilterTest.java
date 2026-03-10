package io.latticepay.security.gcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.latticepay.security.config.LatticeSecurityConfig;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import java.io.IOException;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link GcpIamClientFilter} using Mockito.
 * Tests filter behavior with mocked config and token provider for full control over test scenarios.
 */
@DisplayName("GcpIamClientFilter")
@ExtendWith(MockitoExtension.class)
class GcpIamClientFilterTest {

    private static final String TEST_AUDIENCE = "https://merchant-service-test";
    private static final String TEST_TOKEN = "test-id-token-value";

    @Mock
    private LatticeSecurityConfig mockSecurityConfig;

    @Mock
    private LatticeSecurityConfig.GcpServiceAuth mockGcpServiceAuth;

    @Mock
    private GcpTokenProvider mockTokenProvider;

    @Mock
    private ClientRequestContext mockRequestContext;

    private MultivaluedMap<String, Object> headers;

    @BeforeEach
    void setUp() {
        headers = new MultivaluedHashMap<>();
        lenient().when(mockRequestContext.getHeaders()).thenReturn(headers);
        lenient().when(mockSecurityConfig.gcpServiceAuth()).thenReturn(mockGcpServiceAuth);
    }

    @Nested
    @DisplayName("filter - auth enabled")
    class AuthEnabledTests {

        @Test
        @DisplayName("should add Authorization header when auth enabled and token obtained")
        void shouldAddHeader_whenAuthEnabledAndTokenObtained() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(true);
            when(mockGcpServiceAuth.targetAudience()).thenReturn(Optional.of(TEST_AUDIENCE));
            when(mockTokenProvider.getIdToken(TEST_AUDIENCE)).thenReturn(TEST_TOKEN);

            var filter = new GcpIamClientFilter(mockSecurityConfig, "dev", mockTokenProvider);
            filter.filter(mockRequestContext);

            assertEquals(1, headers.size());
            assertEquals("Bearer " + TEST_TOKEN, headers.getFirst("Authorization"));
            verify(mockTokenProvider).getIdToken(TEST_AUDIENCE);
        }

        @Test
        @DisplayName("should throw IOException in prod profile when token provider fails")
        void shouldThrowIOException_inProdProfile_whenTokenProviderFails() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(true);
            when(mockGcpServiceAuth.targetAudience()).thenReturn(Optional.of(TEST_AUDIENCE));
            var ioException = new IOException("Failed to get token");
            when(mockTokenProvider.getIdToken(TEST_AUDIENCE)).thenThrow(ioException);

            var filter = new GcpIamClientFilter(mockSecurityConfig, "prod", mockTokenProvider);
            var thrown = assertThrows(IOException.class, () -> filter.filter(mockRequestContext));

            assertEquals("Failed to obtain GCP IAM token", thrown.getMessage());
            assertEquals(ioException, thrown.getCause());
            verify(mockTokenProvider).getIdToken(TEST_AUDIENCE);
        }

        @Test
        @DisplayName("should not throw in dev profile when token provider fails")
        void shouldNotThrow_inDevProfile_whenTokenProviderFails() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(true);
            when(mockGcpServiceAuth.targetAudience()).thenReturn(Optional.of(TEST_AUDIENCE));
            when(mockTokenProvider.getIdToken(TEST_AUDIENCE)).thenThrow(new IOException("Failed to get token"));

            var filter = new GcpIamClientFilter(mockSecurityConfig, "dev", mockTokenProvider);
            filter.filter(mockRequestContext);

            assertEquals(0, headers.size());
            verify(mockTokenProvider).getIdToken(TEST_AUDIENCE);
        }

        @Test
        @DisplayName("should not throw in test profile when token provider fails")
        void shouldNotThrow_inTestProfile_whenTokenProviderFails() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(true);
            when(mockGcpServiceAuth.targetAudience()).thenReturn(Optional.of(TEST_AUDIENCE));
            when(mockTokenProvider.getIdToken(TEST_AUDIENCE)).thenThrow(new IOException("Failed to get token"));

            var filter = new GcpIamClientFilter(mockSecurityConfig, "test", mockTokenProvider);
            filter.filter(mockRequestContext);

            assertEquals(0, headers.size());
            verify(mockTokenProvider).getIdToken(TEST_AUDIENCE);
        }
    }

    @Nested
    @DisplayName("filter - auth disabled")
    class AuthDisabledTests {

        @Test
        @DisplayName("should not add header when auth disabled")
        void shouldNotAddHeader_whenAuthDisabled() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(false);

            var filter = new GcpIamClientFilter(mockSecurityConfig, "dev", mockTokenProvider);
            filter.filter(mockRequestContext);

            assertEquals(0, headers.size());
            verify(mockTokenProvider, never()).getIdToken(TEST_AUDIENCE);
        }

        @Test
        @DisplayName("should not add header when target audience is empty")
        void shouldNotAddHeader_whenTargetAudienceEmpty() throws IOException {
            when(mockGcpServiceAuth.enabled()).thenReturn(true);
            when(mockGcpServiceAuth.targetAudience()).thenReturn(Optional.empty());

            var filter = new GcpIamClientFilter(mockSecurityConfig, "dev", mockTokenProvider);
            filter.filter(mockRequestContext);

            assertEquals(0, headers.size());
            verify(mockTokenProvider, never()).getIdToken(anyString());
        }
    }
}
