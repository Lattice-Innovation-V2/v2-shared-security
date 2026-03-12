package io.latticepay.security.swagger;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.latticepay.security.identity.IdentityUtils;
import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import java.util.Set;

/**
 * Security filter that restricts access to internal-only endpoints (Swagger-UI, OpenAPI docs)
 * to internal users only (@latticepay.io email domain).
 * <p>
 * This filter intercepts requests to documentation paths (/q/docs, /q/openapi) and validates
 * that the authenticated user has an internal email domain. External users receive a 403 Forbidden
 * response, while internal users are allowed to proceed.
 * <p>
 * <strong>Security Model:</strong>
 * <ul>
 *   <li>Internal users (admin.dev.* + IAP): Allowed after IAP authentication</li>
 *   <li>External users (api.dev.* + GCIP): Blocked with 403 Forbidden</li>
 *   <li>Unauthenticated users: Blocked by OIDC (401) before reaching this filter</li>
 * </ul>
 * <p>
 * Configuration: {@code latticepay.security.swagger-protection.enabled} (default: true)
 * <p>
 * Priority: 2000 (runs after authentication @Priority(1000), before authorization)
 *
 * @see IdentityUtils#isInternalUser(JsonWebToken)
 * @see LatticeSecurityConfig.SwaggerProtection
 */
@Provider
@PreMatching
@Priority(2000)
public class InternalOnlyFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(InternalOnlyFilter.class);

    /**
     * Paths that require internal user access only.
     * These paths expose sensitive API documentation and should never be accessible to external users.
     */
    private static final Set<String> INTERNAL_ONLY_PATH_PATTERNS = Set.of(
            "/q/docs",
            "/q/openapi"
    );

    private final Instance<LatticeSecurityConfig> configInstance;
    private final Instance<JsonWebToken> jwtInstance;
    private final IdentityUtils identityUtils;

    /**
     * Constructor-injected dependencies for CDI.
     * Uses {@link Instance} for config and JWT so the filter can start even when the config mapping
     * or JWT producer is not yet registered (e.g. multi-tenant OIDC setups where JsonWebToken
     * is only available after tenant resolution).
     *
     * @param configInstance security configuration (swagger protection enabled, etc.)
     * @param jwtInstance    current request's JWT (injected per-request by Quarkus OIDC)
     * @param identityUtils  utility for internal user detection
     */
    public InternalOnlyFilter(Instance<LatticeSecurityConfig> configInstance, Instance<JsonWebToken> jwtInstance, IdentityUtils identityUtils) {
        this.configInstance = configInstance;
        this.jwtInstance = jwtInstance;
        this.identityUtils = identityUtils;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        // Fail closed when config mapping is not available (e.g. SRCFG00027 in some setups)
        if (!configInstance.isResolvable()) {
            LOG.warn("LatticeSecurityConfig not available; aborting request (fail-closed)");
            ctx.abortWith(Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("Security configuration unavailable")
                    .build());
            return;
        }
        LatticeSecurityConfig config = configInstance.get();

        // Check if swagger protection is enabled
        if (!config.swaggerProtection().enabled()) {
            LOG.debug("Swagger protection is disabled, allowing all requests to documentation paths");
            return;
        }

        String path = ctx.getUriInfo().getPath();

        // Check if path matches internal-only patterns
        boolean isInternalPath = INTERNAL_ONLY_PATH_PATTERNS.stream()
                .anyMatch(pattern -> path.endsWith(pattern) ||
                                     path.contains(pattern + "/"));

        if (!isInternalPath) {
            // Not a protected path, allow the request to proceed
            return;
        }

        // Path is protected, validate user is internal
        JsonWebToken jwt = jwtInstance.isResolvable() ? jwtInstance.get() : null;
        if (!identityUtils.isInternalUser(jwt)) {
            String email = identityUtils.getEmail(jwt);
            LOG.warnf("Access denied to documentation path %s for user: %s",
                      path, email != null ? email : "unauthenticated");

            ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                    .entity("Access to documentation is restricted to internal users")
                    .build());
            return;
        }

        // Internal user, allow request to proceed
        LOG.debugf("Access granted to documentation path %s for internal user: %s",
                   path, identityUtils.getEmail(jwt));
    }
}
