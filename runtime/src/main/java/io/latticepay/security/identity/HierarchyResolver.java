package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.ContextNotActiveException;
import jakarta.enterprise.inject.IllegalProductException;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Resolves the authenticated caller's scope from {@link SecurityContext} and JWT claims.
 *
 * Produces a {@link CallerScope} that services use for authorization and data filtering.
 * No database logic -- purely reads from the security context and JWT.
 *
 * Role information comes from the {@link SecurityContext} (populated by
 * {@link LatticeRolesAugmentor}), while identity claims come directly from the JWT.
 */
@ApplicationScoped
public class HierarchyResolver {

    private static final Logger LOG = Logger.getLogger(HierarchyResolver.class);

    private final IdentityUtils identityUtils;
    private final MerchantHierarchyCache merchantHierarchyCache;
    private final LatticeSecurityConfig config;
    private final Instance<RoutingContext> routingContextInstance;

    public HierarchyResolver(IdentityUtils identityUtils, MerchantHierarchyCache merchantHierarchyCache,
                             LatticeSecurityConfig config, Instance<RoutingContext> routingContextInstance) {
        this.identityUtils = identityUtils;
        this.merchantHierarchyCache = merchantHierarchyCache;
        this.config = config;
        this.routingContextInstance = routingContextInstance;
    }

    /**
     * Resolves the caller's scope from SecurityContext + JWT claims.
     *
     * Platform admin: unrestricted (null integratorId, null merchantId).
     * External: scope limited to their integratorId/merchantId.
     * WIF tokens: integrator ID may be derived from the WIF provider ID when not in JWT claims.
     *
     * Fail-closed: unauthenticated callers or tokens with no known role
     * receive {@link CallerScope#ANONYMOUS}; identity claims are never exposed for unknown roles.
     *
     * @param securityContext the security context (may be null)
     * @return the resolved caller scope, or {@link CallerScope#ANONYMOUS} if unauthenticated or unknown role
     */
    public CallerScope resolve(SecurityContext securityContext) {
        if (securityContext == null || securityContext.getUserPrincipal() == null) {
            return CallerScope.ANONYMOUS;
        }
        if (!(securityContext.getUserPrincipal() instanceof JsonWebToken jwt)) {
            return CallerScope.ANONYMOUS;
        }

        String email = identityUtils.getEmail(jwt);
        CallerScope.AuthProvider authProvider = determineAuthProvider(jwt);

        if (securityContext.isUserInRole("platform_admin") || securityContext.isUserInRole("admin")) {
            UUID impersonatedIntegratorId = getImpersonationScope(email);
            return new CallerScope("platform_admin", impersonatedIntegratorId, null, List.of(), null, email, authProvider);
        }

        String role = resolveRole(securityContext);
        if (role == null) {
            return CallerScope.ANONYMOUS;
        }

        // Resolve integrator ID: JWT claim first, then WIF provider fallback
        UUID integratorId = identityUtils.getIntegratorId(jwt)
                .or(() -> {
                    if (authProvider == CallerScope.AuthProvider.WIF) {
                        return identityUtils.getWifProviderIdFromAudience(jwt)
                                .flatMap(pid -> identityUtils.extractIntegratorIdFromProvider(
                                        pid, config.wif().providerPrefix()))
                                .flatMap(this::parseUuid);
                    }
                    return Optional.empty();
                })
                .orElse(null);

        return new CallerScope(
                role,
                integratorId,
                identityUtils.getMerchantId(jwt).orElse(null),
                identityUtils.getPermissions(jwt),
                identityUtils.getTier(jwt).orElse(null),
                email,
                authProvider
        );
    }

    private static final String[] EXTERNAL_ROLES = {
            "integrator_admin", "integrator_readonly",
            "merchant_admin", "merchant_readonly"
    };

    /**
     * Resolves the first matching external role from SecurityContext (populated by {@link LatticeRolesAugmentor}).
     * Order of {@link #EXTERNAL_ROLES} defines precedence.
     */
    private static String resolveRole(SecurityContext securityContext) {
        return Stream.of(EXTERNAL_ROLES)
                .filter(securityContext::isUserInRole)
                .findFirst()
                .orElse(null);
    }

    /** Well-known issuer for GCP IAP JWT tokens (admin portal). */
    private static final String IAP_ISSUER = "https://cloud.google.com/iap";

    /**
     * Determines the authentication provider from the JWT issuer claim.
     *
     * Order: WIF first (by issuer), then IAP (by issuer), then GCIP as fallback.
     * IAP is identified only when the token's {@code iss} matches the IAP issuer URL;
     * internal email domain is not used to infer IAP (business rule: provider is
     * issuer-based, not identity-based).
     */
    private CallerScope.AuthProvider determineAuthProvider(JsonWebToken jwt) {
        if (identityUtils.isWifToken(jwt)) {
            return CallerScope.AuthProvider.WIF;
        }
        String iss = jwt != null ? jwt.getIssuer() : null;
        if (IAP_ISSUER.equals(iss)) {
            return CallerScope.AuthProvider.IAP;
        }
        return CallerScope.AuthProvider.GCIP;
    }

    /**
     * Resolves the set of merchant IDs the current caller may access.
     *
     * - **Integrator** with valid integrator_id: returns set via cache/SPI (full subtree or
     *   direct merchants per hierarchy rules).
     * - **Integrator** with missing integrator_id: throws {@link jakarta.ws.rs.NotAuthorizedException}.
     * - **Admin**: returns empty set (convention: empty = unrestricted; service checks
     *   {@link CallerScope#isPlatformAdmin()} first and skips filtering).
     * - **Merchant** / **Anonymous**: returns empty set (merchant self-access uses
     *   {@link CallerScope#isMerchant()} and {@link CallerScope#requireMerchantId()} directly).
     *
     * @param securityContext the JAX-RS security context
     * @return unmodifiable set of accessible merchant IDs, empty if non-integrator
     * @throws jakarta.ws.rs.NotAuthorizedException if integrator has no integrator_id claim
     */
    public Set<UUID> resolveAccessibleMerchantIds(SecurityContext securityContext) {
        CallerScope scope = resolve(securityContext);
        if (!scope.isIntegrator()) {
            return Set.of();
        }
        UUID integratorId = scope.requireIntegratorId();
        return merchantHierarchyCache.getAccessibleMerchantIds(integratorId);
    }

    /**
     * Reads the impersonation scope from the {@code X-Impersonate-Integrator-Id} header.
     * Only meaningful for platform_admin callers; the header is ignored for other roles.
     * Successful parse and invalid attempts are audit-logged.
     *
     * @param callerPrincipal the authenticated caller identity (e.g. email) for audit
     * @return the impersonated integrator UUID, or null if not present or invalid
     */
    private UUID getImpersonationScope(String callerPrincipal) {
        if (!routingContextInstance.isResolvable()) return null;
        final io.vertx.core.http.HttpServerRequest request;
        try {
            RoutingContext routingContext = routingContextInstance.get();
            request = routingContext.request();
        } catch (IllegalProductException | ContextNotActiveException ignored) {
            // No active HTTP request (e.g. test or non-request context) — producer returned null or request context inactive
            return null;
        }
        String header = request.getHeader("X-Impersonate-Integrator-Id");
        if (header == null || header.isBlank()) {
            return null;
        }
        String trimmed = header.trim();
        try {
            UUID uuid = UUID.fromString(trimmed);
            String requestId = request.getHeader("X-Request-Id");
            String remote = request.connection() != null && request.connection().remoteAddress() != null
                    ? request.connection().remoteAddress().hostAddress()
                    : null;
            LOG.infov(
                    "Impersonation applied: integratorId={0} caller={1} requestId={2} remote={3}",
                    uuid, callerPrincipal != null ? callerPrincipal : "unknown",
                    requestId != null ? requestId : "-", remote != null ? remote : "-");
            return uuid;
        } catch (IllegalArgumentException ignored) {
            LOG.warnv("Impersonation attempt rejected: invalid X-Impersonate-Integrator-Id value caller={0} value={1}",
                    callerPrincipal != null ? callerPrincipal : "unknown", trimmed);
            return null;
        }
    }

    private Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }
}
