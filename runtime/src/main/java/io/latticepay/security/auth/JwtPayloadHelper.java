package io.latticepay.security.auth;

import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Minimal JWT payload parsing without verification (decode only).
 * Used solely to read the {@code iss} claim for dev-tenant selection in
 * {@link HybridTenantConfigResolver}. Must not be used for authorization
 * decisions; only verified tokens (e.g. after Quarkus OIDC validation) are
 * safe for that.
 */
final class JwtPayloadHelper {

    /** Captures iss value (including empty string). */
    private static final Pattern ISS_PATTERN = Pattern.compile("\"iss\"\\s*:\\s*\"([^\"]*)\"");

    private JwtPayloadHelper() {
    }

    /**
     * Decodes the JWT payload (second segment) and returns the {@code iss} claim if present.
     * No signature verification is performed.
     *
     * @param bearerToken the raw Bearer token (e.g. from {@code Authorization: Bearer <token>})
     * @return the issuer string, or empty if the token is malformed or has no {@code iss} claim
     */
    static Optional<String> getIssuerFromBearerToken(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return Optional.empty();
        }
        String[] parts = bearerToken.split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            if (decoded == null || decoded.length == 0) {
                return Optional.empty();
            }
            String payload = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
            var matcher = ISS_PATTERN.matcher(payload);
            if (matcher.find()) {
                return Optional.of(matcher.group(1));
            }
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
