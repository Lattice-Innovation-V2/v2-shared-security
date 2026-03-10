package io.latticepay.security.gcp;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdToken;
import com.google.auth.oauth2.IdTokenProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link DefaultGcpTokenProvider}.
 * Uses the package-private credentials supplier constructor to cover both branches and all lines.
 */
@DisplayName("DefaultGcpTokenProvider")
@ExtendWith(MockitoExtension.class)
class DefaultGcpTokenProviderTest {

    private static final String AUDIENCE = "https://test-audience.example.com";
    private static final String EXPECTED_TOKEN_VALUE = "test-id-token-value";

    @Mock
    private Supplier<GoogleCredentials> credentialsSupplier;

    private DefaultGcpTokenProvider provider;

    @BeforeEach
    void setUp() {
        provider = new DefaultGcpTokenProvider(credentialsSupplier);
    }

    @Nested
    @DisplayName("getIdToken - credentials not IdTokenProvider")
    class CredentialsNotIdTokenProvider {

        @Test
        @DisplayName("throws IOException with descriptive message when credentials do not support ID tokens")
        void throwsIOExceptionWithMessage() {
            var credentials = mock(GoogleCredentials.class);
            when(credentialsSupplier.get()).thenReturn(credentials);

            var ex = assertThrows(IOException.class, () -> provider.getIdToken(AUDIENCE));

            assertAll(
                    () -> assertEquals(
                            "Credentials do not support ID token generation. "
                                    + "Ensure you are running with a service account or have "
                                    + "GOOGLE_APPLICATION_CREDENTIALS set correctly.",
                            ex.getMessage()),
                    () -> verify(credentialsSupplier).get());
        }
    }

    @Nested
    @DisplayName("getIdToken - credentials are IdTokenProvider")
    class CredentialsAreIdTokenProvider {

        @Test
        @DisplayName("returns token value when credentials support ID token generation")
        void returnsTokenValue() throws IOException {
            var idToken = mock(IdToken.class);
            when(idToken.getTokenValue()).thenReturn(EXPECTED_TOKEN_VALUE);

            var credentials = mock(GoogleCredentials.class,
                    withSettings().extraInterfaces(IdTokenProvider.class));
            when(credentialsSupplier.get()).thenReturn(credentials);
            when(((IdTokenProvider) credentials).idTokenWithAudience(eq(AUDIENCE), any()))
                    .thenReturn(idToken);

            var result = provider.getIdToken(AUDIENCE);

            assertEquals(EXPECTED_TOKEN_VALUE, result);
            verify(credentialsSupplier).get();
        }
    }

    @Nested
    @DisplayName("getIdToken - credentials supplier throws")
    class CredentialsSupplierThrows {

        @Test
        @DisplayName("propagates IOException when credentials supplier throws UncheckedIOException")
        void propagatesIOException() {
            var cause = new IOException("No credentials");
            doAnswer(invocation -> { throw new UncheckedIOException(cause); })
                    .when(credentialsSupplier)
                    .get();

            var ex = assertThrows(IOException.class, () -> provider.getIdToken(AUDIENCE));

            assertEquals(cause, ex);
            verify(credentialsSupplier).get();
        }
    }
}
