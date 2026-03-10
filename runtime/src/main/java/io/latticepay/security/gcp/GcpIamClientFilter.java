package io.latticepay.security.gcp;

import io.latticepay.security.config.LatticeSecurityConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import java.io.IOException;

/**
 * JAX-RS Client filter that adds GCP IAM identity token to outgoing requests.
 * Used for service-to-service authentication in GCP.
 * <p>
 * When enabled, this filter attaches a GCP IAM identity token to all outbound REST client requests.
 * The token is obtained using {@link GcpTokenProvider} and added as {@code Authorization: Bearer <token>}.
 * <p>
 * Configuration:
 * <ul>
 *   <li>{@code latticepay.security.gcp-service-auth.enabled} - Enable/disable the filter</li>
 *   <li>{@code latticepay.security.gcp-service-auth.target-audience} - Target audience for the identity token</li>
 * </ul>
 */
@ApplicationScoped
public class GcpIamClientFilter implements ClientRequestFilter {

    private static final Logger LOG = Logger.getLogger(GcpIamClientFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final LatticeSecurityConfig.GcpServiceAuth config;
    private final String profile;
    private final GcpTokenProvider tokenProvider;

    public GcpIamClientFilter(
            LatticeSecurityConfig securityConfig,
            @ConfigProperty(name = "quarkus.profile", defaultValue = "dev") String profile,
            GcpTokenProvider tokenProvider) {
        this.config = securityConfig.gcpServiceAuth();
        this.profile = profile;
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        if (!config.enabled() || config.targetAudience().isEmpty()) {
            LOG.debug("GCP IAM auth disabled or no target audience configured");
            return;
        }

        String audience = config.targetAudience().get();
        try {
            var idToken = tokenProvider.getIdToken(audience);
            requestContext.getHeaders().add(AUTHORIZATION_HEADER, BEARER_PREFIX + idToken);
            LOG.debugf("Added GCP IAM token for audience: %s", audience);
        } catch (Exception e) {
            LOG.warnf("Failed to obtain GCP IAM token: %s", e.getMessage());
            // In development, we might want to continue without auth
            if (isProduction()) {
                throw new IOException("Failed to obtain GCP IAM token", e);
            }
        }
    }

    private boolean isProduction() {
        return "prod".equals(profile) || "production".equals(profile);
    }
}
