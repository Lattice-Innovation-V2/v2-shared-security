package io.latticepay.security.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Shared test utility for building minimal JWT strings in auth tests.
 * Use this instead of duplicating JWT construction across JwtPayloadHelperTest and HybridTenantConfigResolverTest.
 */
public final class TestJwtFactory {

    private TestJwtFactory() {
    }

    /**
     * Base64url-encodes a string (no padding). Useful for building custom payload/header segments in tests.
     */
    public static String base64UrlEncode(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Builds a minimal three-part JWT with the given {@code iss} in the payload (no real signature).
     * Third segment is literal {@code "x"} (not base64); sufficient for issuer extraction and tenant selection tests.
     */
    public static String minimalJwtWithIss(String iss) {
        String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        String payload = "{\"iss\":\"" + iss + "\",\"sub\":\"test\"}";
        return base64UrlEncode(header) + "." + base64UrlEncode(payload) + ".x";
    }
}
