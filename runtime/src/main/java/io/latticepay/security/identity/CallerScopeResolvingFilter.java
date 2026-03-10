package io.latticepay.security.identity;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * JAX-RS filter that resolves the caller's identity on every request
 * and stores it in the request-scoped {@link RequestCallerScope} bean.
 *
 * Runs after authentication (AUTHENTICATION + 10) so that
 * {@link jakarta.ws.rs.core.SecurityContext} is already populated
 * by Quarkus OIDC / {@link io.latticepay.security.auth.HybridTenantConfigResolver}.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 10)
public class CallerScopeResolvingFilter implements ContainerRequestFilter {

    @Inject
    HierarchyResolver hierarchyResolver;

    @Inject
    RequestCallerScope requestCallerScope;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        CallerScope scope = hierarchyResolver.resolve(requestContext.getSecurityContext());
        requestCallerScope.setScope(scope);
    }
}
