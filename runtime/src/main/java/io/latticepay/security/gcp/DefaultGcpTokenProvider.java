package io.latticepay.security.gcp;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.function.Supplier;

/**
 * Default production implementation of {@link GcpTokenProvider} that uses
 * Google Application Default Credentials to obtain GCP IAM identity tokens.
 */
@ApplicationScoped
public class DefaultGcpTokenProvider implements GcpTokenProvider {

    private final Supplier<GoogleCredentials> credentialsSupplier;

    public DefaultGcpTokenProvider() {
        this(() -> {
            try {
                return GoogleCredentials.getApplicationDefault();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    /**
     * Package-private for tests; allows injecting a credentials supplier.
     */
    DefaultGcpTokenProvider(Supplier<GoogleCredentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
    }

    @Override
    public String getIdToken(String audience) throws IOException {
        final GoogleCredentials credentials;
        try {
            credentials = credentialsSupplier.get();
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }

        if (!(credentials instanceof IdTokenProvider)) {
            throw new IOException("Credentials do not support ID token generation. " +
                    "Ensure you are running with a service account or have " +
                    "GOOGLE_APPLICATION_CREDENTIALS set correctly.");
        }

        var idTokenCredentials = IdTokenCredentials.newBuilder()
                .setIdTokenProvider((IdTokenProvider) credentials)
                .setTargetAudience(audience)
                .build();

        idTokenCredentials.refresh();
        return idTokenCredentials.getIdToken().getTokenValue();
    }
}
