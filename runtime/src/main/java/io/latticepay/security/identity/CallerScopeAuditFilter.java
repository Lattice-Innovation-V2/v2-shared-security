package io.latticepay.security.identity;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

/**
 * Audit filter that logs caller identity for write operations (POST, PUT, DELETE, PATCH).
 * Runs after {@link CallerScopeResolvingFilter} has populated the {@link RequestCallerScope}.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 20)
public class CallerScopeAuditFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(CallerScopeAuditFilter.class);

    @Inject
    RequestCallerScope callerScope;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        if ("POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method)) {
            LOG.infof("AUDIT: %s %s | caller=%s role=%s integratorId=%s merchantId=%s admin=%s",
                    method,
                    requestContext.getUriInfo().getRequestUri().getPath(),
                    callerScope.email(),
                    callerScope.role(),
                    callerScope.integratorId(),
                    callerScope.merchantId(),
                    callerScope.isPlatformAdmin());
        }
    }
}
