package io.latticepay.security.identity;

/**
 * Enumeration of caller types for authenticated requests.
 * <p>
 * Used by {@link IdentityUtils#getCallerType(org.eclipse.microprofile.jwt.JsonWebToken)}
 * to classify the authenticated caller.
 */
public enum CallerType {
    /**
     * Internal Google Workspace user (via IAP).
     * Email ends with the configured internal domain (default: "@latticepay.io").
     * These users typically have full access to all resources.
     */
    INTERNAL_USER,

    /**
     * External customer (via GCIP, WIF, or STS token exchange).
     * Has {@code integrator_id} and optionally {@code merchant_id} claims.
     * These users are restricted to their hierarchy (self + descendants).
     */
    EXTERNAL_USER
}
