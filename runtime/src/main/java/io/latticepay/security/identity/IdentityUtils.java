package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.JsonWebToken;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Utility class for extracting identity information from JWT tokens.
 *
 * Works with IAP, GCIP, and WIF tokens (via MicroProfile JWT {@link JsonWebToken}).
 * Provides methods for internal user detection, email extraction, integrator/merchant ID parsing,
 * claim extraction, and caller type classification.
 */
@ApplicationScoped
public class IdentityUtils {

    private static final String EMAIL_CLAIM = "email";
    private static final String INTEGRATOR_ID_CLAIM = "integrator_id";
    private static final String MERCHANT_ID_CLAIM = "merchant_id";
    private static final String PERMISSIONS_CLAIM = "permissions";
    private static final String TIER_CLAIM = "tier";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /** Issuer used by GCP Workforce Identity Federation STS tokens. */
    public static final String WIF_ISSUER = "https://sts.googleapis.com";

    private final String internalDomain;
    private final String roleClaim;

    public IdentityUtils(LatticeSecurityConfig config) {
        this.internalDomain = config.internalDomain();
        this.roleClaim = config.roleClaim();
    }

    /**
     * Checks if the user is an internal user based on email domain.
     *
     * An internal user is one whose email ends with the configured internal domain
     * (default: "@latticepay.io"). This works for both IAP and GCIP tokens.
     *
     * @param jwt the JWT token (may be null)
     * @return true if the user's email ends with the internal domain, false otherwise
     */
    public boolean isInternalUser(JsonWebToken jwt) {
        return Optional.ofNullable(getEmail(jwt))
                .map(email -> email.toLowerCase().endsWith(internalDomain.toLowerCase()))
                .orElse(false);
    }

    /**
     * Extracts the email address from the JWT token.
     *
     * First attempts to read the {@code email} claim. If not present, falls back to
     * {@link JsonWebToken#getName()}.
     *
     * @param jwt the JWT token (may be null)
     * @return the email address, or null if not available
     */
    public String getEmail(JsonWebToken jwt) {
        if (jwt == null) {
            return null;
        }
        return Optional.ofNullable(jwt.getClaim(EMAIL_CLAIM))
                .map(Object::toString)
                .orElseGet(jwt::getName);
    }

    /**
     * Extracts the integrator_id claim from the JWT token as a UUID.
     *
     * Present for both integrator and merchant users. This is the integrator's
     * database primary key UUID. Falls back to {@code gcip.firebase.sign_in_attributes.integrator_id}
     * for IAP JWTs backed by GCIP External Identities.
     *
     * @param jwt the JWT token (may be null)
     * @return the integrator ID as a UUID, or empty if not present or invalid
     */
    public Optional<UUID> getIntegratorId(JsonWebToken jwt) {
        Optional<UUID> topLevel = getUuidClaim(jwt, INTEGRATOR_ID_CLAIM);
        if (topLevel.isPresent()) return topLevel;
        return getGcipSignInAttribute(jwt, INTEGRATOR_ID_CLAIM)
                .flatMap(this::parseUuid);
    }

    /**
     * Extracts the merchant_id claim from the JWT token as a UUID.
     *
     * Present only for merchant users. This is the merchant's database primary key UUID.
     * Falls back to {@code gcip.firebase.sign_in_attributes.merchant_id}
     * for IAP JWTs backed by GCIP External Identities.
     *
     * @param jwt the JWT token (may be null)
     * @return the merchant ID as a UUID, or empty if not present or invalid
     */
    public Optional<UUID> getMerchantId(JsonWebToken jwt) {
        Optional<UUID> topLevel = getUuidClaim(jwt, MERCHANT_ID_CLAIM);
        if (topLevel.isPresent()) return topLevel;
        return getGcipSignInAttribute(jwt, MERCHANT_ID_CLAIM)
                .flatMap(this::parseUuid);
    }

    /**
     * Extracts the permissions claim from the JWT token.
     *
     * The permissions claim is a list of fine-grained permission strings
     * (e.g. "merchants:read", "payments:read"). Falls back to
     * {@code gcip.firebase.sign_in_attributes.permissions} for IAP JWTs
     * backed by GCIP External Identities.
     *
     * @param jwt the JWT token (may be null)
     * @return the list of permissions, or empty list if not present
     */
    public List<String> getPermissions(JsonWebToken jwt) {
        if (jwt == null) {
            return List.of();
        }
        Object claim = jwt.getClaim(PERMISSIONS_CLAIM);
        if (claim == null) {
            // Fall back to GCIP nested permissions
            claim = getGcipSignInAttributeRaw(jwt, PERMISSIONS_CLAIM);
        }
        if (claim == null) {
            return List.of();
        }
        if (claim instanceof Collection<?> collection) {
            return collection.stream()
                    .map(Object::toString)
                    .toList();
        }
        return List.of();
    }

    /**
     * Extracts the tier claim from the JWT token.
     *
     * @param jwt the JWT token (may be null)
     * @return the tier string (e.g. "production", "sandbox"), or empty if not present
     */
    public Optional<String> getTier(JsonWebToken jwt) {
        return getStringClaim(jwt, TIER_CLAIM);
    }

    /**
     * Determines the caller type based on JWT claims.
     *
     * Classification logic:
     * - If {@link #isInternalUser(JsonWebToken)} returns true -> {@link CallerType#INTERNAL_USER}
     * - Otherwise -> {@link CallerType#EXTERNAL_USER}
     *
     * @param jwt the JWT token (may be null)
     * @return the caller type, or {@link CallerType#EXTERNAL_USER} if jwt is null
     */
    public CallerType getCallerType(JsonWebToken jwt) {
        if (isInternalUser(jwt)) {
            return CallerType.INTERNAL_USER;
        }
        return CallerType.EXTERNAL_USER;
    }

    /**
     * Extracts the role claim from the JWT token.
     *
     * The claim name is configurable (default: "role"). This is typically present
     * in GCIP and WIF tokens for external users. For IAP JWTs backed by
     * GCIP External Identities, falls back to {@code gcip.firebase.sign_in_attributes.role}.
     *
     * @param jwt the JWT token (may be null)
     * @return the role as a string, or empty if not present
     */
    public Optional<String> getRole(JsonWebToken jwt) {
        Optional<String> topLevel = getStringClaim(jwt, roleClaim);
        if (topLevel.isPresent()) return topLevel;
        return getGcipSignInAttribute(jwt, roleClaim);
    }

    /**
     * Returns true if the JWT was issued by the GCP STS endpoint (Workforce Identity Federation).
     *
     * @param jwt the JWT token (may be null)
     * @return true if {@code iss} equals {@value #WIF_ISSUER}
     */
    public boolean isWifToken(JsonWebToken jwt) {
        return jwt != null && WIF_ISSUER.equals(jwt.getIssuer());
    }

    /**
     * Extracts the WIF provider ID from the JWT audience claim.
     * The audience for WIF tokens follows the format:
     * {@code //iam.googleapis.com/locations/global/workforcePools/{pool}/providers/{provider}}
     *
     * @param jwt the JWT token (may be null)
     * @return the provider ID (last path segment of the audience URI), or empty
     */
    public Optional<String> getWifProviderIdFromAudience(JsonWebToken jwt) {
        if (jwt == null || jwt.getAudience() == null || jwt.getAudience().isEmpty()) {
            return Optional.empty();
        }
        String aud = jwt.getAudience().iterator().next();
        if (aud == null || aud.isBlank()) {
            return Optional.empty();
        }
        int lastSlash = aud.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == aud.length() - 1) {
            return Optional.empty();
        }
        return Optional.of(aud.substring(lastSlash + 1));
    }

    /**
     * Extracts the integrator identifier from a WIF provider ID by stripping the configured prefix.
     *
     * @param providerId the WIF provider ID (e.g. "provider-integrator-int_abc123")
     * @param prefix     the provider prefix to strip (e.g. "provider-integrator-")
     * @return the integrator identifier, or empty if the provider ID does not match the prefix
     */
    public Optional<String> extractIntegratorIdFromProvider(String providerId, String prefix) {
        if (providerId == null || prefix == null || !providerId.startsWith(prefix)) {
            return Optional.empty();
        }
        String id = providerId.substring(prefix.length());
        return id.isBlank() ? Optional.empty() : Optional.of(id);
    }

    /**
     * Reads a string claim from the nested {@code gcip.firebase.sign_in_attributes} structure
     * present in IAP JWTs backed by GCIP External Identities.
     */
    private Optional<String> getGcipSignInAttribute(JsonWebToken jwt, String attributeName) {
        Object value = getGcipSignInAttributeRaw(jwt, attributeName);
        return value != null ? Optional.of(value.toString()) : Optional.empty();
    }

    /**
     * Reads a raw claim value from the nested {@code gcip.firebase.sign_in_attributes} structure.
     */
    private Object getGcipSignInAttributeRaw(JsonWebToken jwt, String attributeName) {
        return Optional.ofNullable(jwt)
                .map(token -> token.getClaim("gcip"))
                .flatMap(IdentityUtils::asOptionalMap)
                .flatMap(gcip -> asOptionalMap(gcip.get("firebase")))
                .flatMap(firebase -> asOptionalMap(firebase.get("sign_in_attributes")))
                .flatMap(attrs -> Optional.ofNullable(attrs.get(attributeName)))
                .orElse(null);
    }

    /** Returns the value as a non-empty map, or empty if not a map or empty. */
    private static Optional<Map<String, Object>> asOptionalMap(Object obj) {
        Map<String, Object> map = toMap(obj);
        return map.isEmpty() ? Optional.empty() : Optional.of(map);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> toMap(Object obj) {
        if (obj instanceof Map) return (Map<String, Object>) obj;
        if (obj instanceof String str) {
            try {
                return OBJECT_MAPPER.readValue(str, Map.class);
            } catch (Exception ignored) {
                return Collections.emptyMap();
            }
        }
        return Collections.emptyMap();
    }

    private Optional<String> getStringClaim(JsonWebToken jwt, String claimName) {
        return Optional.ofNullable(jwt)
                .map(token -> token.getClaim(claimName))
                .map(Object::toString);
    }

    private Optional<UUID> getUuidClaim(JsonWebToken jwt, String claimName) {
        return Optional.ofNullable(jwt)
                .map(token -> token.getClaim(claimName))
                .map(Object::toString)
                .flatMap(this::parseUuid);
    }

    /**
     * Parses a string value as a UUID.
     * Returns empty if parsing fails.
     */
    private Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

}
