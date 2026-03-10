package io.latticepay.security.gcp;

import java.io.IOException;

/**
 * Provider interface for obtaining GCP IAM identity tokens.
 * Allows for testability by enabling mock implementations.
 */
public interface GcpTokenProvider {

    /**
     * Obtains an ID token for the specified audience.
     *
     * @param audience the target audience for the ID token
     * @return the ID token as a string
     * @throws IOException if the token cannot be obtained
     */
    String getIdToken(String audience) throws IOException;
}
