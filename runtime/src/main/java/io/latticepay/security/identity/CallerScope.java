package io.latticepay.security.identity;

import java.util.List;
import java.util.UUID;

/**
 * Immutable record encapsulating the resolved caller identity and scope.
 *
 * Built by {@link HierarchyResolver#resolve(jakarta.ws.rs.core.SecurityContext)} from
 * the authenticated {@code SecurityContext} and JWT claims. Services use this instead
 * of directly inspecting roles and claims.
 *
 * @param role          the authorization role ("platform_admin", "integrator_admin", etc.), or null if anonymous
 * @param integratorId  the integrator UUID from JWT ({@code integrator_id} claim), or null for admins
 * @param merchantId    the merchant UUID from JWT ({@code merchant_id} claim), or null for non-merchant users
 * @param permissions   fine-grained permissions from JWT ({@code permissions} claim), never null
 * @param tier          the tier from JWT ({@code tier} claim, e.g. "production", "sandbox"), or null
 * @param email         the caller's email address
 * @param authProvider  the authentication provider that issued the token, or null if anonymous
 */
public record CallerScope(
        String role,
        UUID integratorId,
        UUID merchantId,
        List<String> permissions,
        String tier,
        String email,
        AuthProvider authProvider
) {
    public static final CallerScope ANONYMOUS = new CallerScope(null, null, null, List.of(), null, null, null);

    /**
     * Authentication provider that issued the caller's token.
     */
    public enum AuthProvider {
        /** Internal user via Identity-Aware Proxy. */
        IAP,
        /** External user via Firebase/GCIP. */
        GCIP,
        /** External user via Workforce Identity Federation (STS token exchange). */
        WIF,
        /** Dev mode self-issued JWT (local development only). */
        DEV
    }

    public boolean isPlatformAdmin() {
        return "platform_admin".equals(role);
    }

    public boolean isIntegratorAdmin() {
        return "integrator_admin".equals(role);
    }

    public boolean isIntegratorReadonly() {
        return "integrator_readonly".equals(role);
    }

    public boolean isIntegrator() {
        return isIntegratorAdmin() || isIntegratorReadonly();
    }

    public boolean isMerchantAdmin() {
        return "merchant_admin".equals(role);
    }

    public boolean isMerchantReadonly() {
        return "merchant_readonly".equals(role);
    }

    public boolean isMerchant() {
        return isMerchantAdmin() || isMerchantReadonly();
    }

    public boolean isAnonymous() {
        return role == null;
    }

    /**
     * Returns true if the caller has the specified permission.
     *
     * @param permission the permission to check (e.g. "merchants:read")
     * @return true if the permission is present in the caller's permissions list
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    /**
     * Returns the integrator ID, throwing if absent.
     */
    public UUID requireIntegratorId() {
        if (integratorId == null) {
            throw new jakarta.ws.rs.NotAuthorizedException("Missing integrator_id claim in JWT");
        }
        return integratorId;
    }

    /**
     * Returns the merchant ID, throwing if absent.
     */
    public UUID requireMerchantId() {
        if (merchantId == null) {
            throw new jakarta.ws.rs.NotAuthorizedException("Missing merchant_id claim in JWT");
        }
        return merchantId;
    }
}
