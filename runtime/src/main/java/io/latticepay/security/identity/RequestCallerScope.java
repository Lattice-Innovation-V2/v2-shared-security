package io.latticepay.security.identity;

import jakarta.enterprise.context.RequestScoped;

/**
 * Request-scoped holder for the resolved {@link CallerScope}.
 *
 * Populated per-request by {@link CallerScopeResolvingFilter} using
 * {@link HierarchyResolver}. Services inject this bean to access
 * the authenticated caller's identity without calling HierarchyResolver directly.
 *
 * <p>Usage:
 * <pre>{@code
 * @Inject RequestCallerScope callerScope;
 *
 * public void myMethod() {
 *     if (callerScope.isPlatformAdmin()) { ... }
 *     UUID integratorId = callerScope.integratorId();
 *     String email = callerScope.email();
 * }
 * }</pre>
 */
@RequestScoped
public class RequestCallerScope {

    private CallerScope scope = CallerScope.ANONYMOUS;

    /** Package-private setter used by {@link CallerScopeResolvingFilter}. */
    void setScope(CallerScope scope) {
        this.scope = scope != null ? scope : CallerScope.ANONYMOUS;
    }

    /** Returns the underlying immutable {@link CallerScope} record. */
    public CallerScope getScope() {
        return scope;
    }

    // --- Delegate convenience methods ---

    public boolean isPlatformAdmin() { return scope.isPlatformAdmin(); }
    public boolean isIntegrator() { return scope.isIntegrator(); }
    public boolean isMerchant() { return scope.isMerchant(); }
    public boolean isAnonymous() { return scope.isAnonymous(); }

    public java.util.UUID integratorId() { return scope.integratorId(); }
    public java.util.UUID merchantId() { return scope.merchantId(); }
    public String email() { return scope.email(); }
    public String role() { return scope.role(); }
    public String tier() { return scope.tier(); }
    public java.util.List<String> permissions() { return scope.permissions(); }
    public CallerScope.AuthProvider authProvider() { return scope.authProvider(); }

    public boolean hasPermission(String permission) { return scope.hasPermission(permission); }
    public java.util.UUID requireIntegratorId() { return scope.requireIntegratorId(); }
    public java.util.UUID requireMerchantId() { return scope.requireMerchantId(); }
}
