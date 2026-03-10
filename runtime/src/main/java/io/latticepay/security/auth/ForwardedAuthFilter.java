package io.latticepay.security.auth;

import io.latticepay.security.config.LatticeSecurityConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.http.HttpServerRequest;
import org.jboss.logging.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Copies {@value #FORWARDED_AUTH} into the standard {@code Authorization} header only when
 * the request is from a trusted source (see {@link #isTrustedSource(HttpServerRequest)}).
 * <p>
 * <strong>Security:</strong> The API Gateway (or ingress) MUST strip or never forward
 * {@value #FORWARDED_AUTH} from untrusted clients. This filter is a second line of defense:
 * it only copies the header when {@code latticepay.security.forwarded-auth.enabled} is true
 * and, if configured, the request comes from a trusted proxy IP.
 */
@ApplicationScoped
public class ForwardedAuthFilter {

    private static final Logger LOG = Logger.getLogger(ForwardedAuthFilter.class);
    /** Header set by the API Gateway with the validated Bearer token; copied to Authorization when trusted. */
    private static final String FORWARDED_AUTH = "X-Forwarded-Authorization";

    /** Value used by Pulumi/GCP when no trusted proxy IPs (env vars cannot be empty). Treated as empty. */
    private static final String NONE_PLACEHOLDER = "NONE";

    private final LatticeSecurityConfig.ForwardedAuth config;
    private final Set<InetAddress> trustedProxyInetAddrs;

    public ForwardedAuthFilter(LatticeSecurityConfig securityConfig) {
        this.config = securityConfig.forwardedAuth();
        this.trustedProxyInetAddrs = parseTrustedProxyIps(config.trustedProxyIps());
    }

    /**
     * Parses configured comma-separated IPs into a set of {@link InetAddress} for canonical comparison
     * (e.g. IPv6 normalization). Invalid entries are logged and skipped.
     * The value {@value #NONE_PLACEHOLDER} (case-insensitive) is treated as empty, for use when
     * the environment cannot set an empty value (e.g. Pulumi/GCP Cloud Run).
     */
    private static Set<InetAddress> parseTrustedProxyIps(String config) {
        if (config == null || config.isBlank() || config.trim().equalsIgnoreCase(NONE_PLACEHOLDER)) {
            return Set.of();
        }
        return Stream.of(config.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(ForwardedAuthFilter::parseInetAddress)
                .flatMap(Optional::stream)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private static Optional<InetAddress> parseInetAddress(String host) {
        try {
            return Optional.of(InetAddress.getByName(host));
        } catch (UnknownHostException e) {
            LOG.warnv(e, "Invalid trusted-proxy-ip, skipping: %s", host);
            return Optional.empty();
        }
    }

    /**
     * Registers the filter that conditionally copies {@value #FORWARDED_AUTH} to {@code Authorization}.
     * Copy is performed only when the request is from a trusted source; otherwise a warning is logged.
     */
    public void register(@Observes Filters filters) {
        if (!config.enabled()) {
            LOG.debug("ForwardedAuthFilter is disabled");
            return;
        }

        filters.register(rc -> {
            String forwarded = rc.request().getHeader(FORWARDED_AUTH);
            if (forwarded != null && !forwarded.isBlank()) {
                if (rc.request().getHeader("Authorization") != null) {
                    // Already have Authorization; do not overwrite
                    rc.next();
                    return;
                }
                if (isTrustedSource(rc.request())) {
                    rc.request().headers().set("Authorization", forwarded);
                    LOG.debugv("Copied X-Forwarded-Authorization to Authorization");
                } else {
                    String remote = getRemoteAddress(rc.request()).map(InetAddress::getHostAddress).orElse("unknown");
                    LOG.warnv(
                            "Dropping X-Forwarded-Authorization from untrusted source (remote=%s). " +
                                    "API Gateway MUST strip this header from untrusted clients.",
                            remote);
                }
            }
            rc.next();
        }, 100); // Priority 100: run before OIDC auth handler
    }

    /**
     * Returns true if the request is allowed to supply {@value #FORWARDED_AUTH}.
     * When {@code enabled} is false, no source is trusted.
     * When it is true and {@code trusted-proxy-ips} is empty, all sources are trusted (e.g. only gateway can reach the service).
     * When {@code trusted-proxy-ips} is set, only those remote addresses are trusted.
     * Comparison uses {@link InetAddress} equality for correct IPv6 canonicalization.
     */
    private boolean isTrustedSource(HttpServerRequest request) {
        if (!config.enabled()) {
            return false;
        }
        if (trustedProxyInetAddrs.isEmpty()) {
            return true;
        }
        return getRemoteAddress(request).map(trustedProxyInetAddrs::contains).orElse(false);
    }

    /**
     * Returns the request's remote address as an {@link InetAddress} for canonical comparison.
     * Parses the Vert.x remote address via {@link InetAddress#getByName(String)}; logs and returns empty on parse failure.
     */
    private Optional<InetAddress> getRemoteAddress(HttpServerRequest request) {
        String host;
        try {
            if (request.connection() == null || request.connection().remoteAddress() == null) {
                return Optional.empty();
            }
            host = request.connection().remoteAddress().hostAddress();
            if (host == null || host.isBlank()) {
                return Optional.empty();
            }
        } catch (Exception e) {
            LOG.debugv(e, "Could not get remote address from connection");
            return Optional.empty();
        }
        try {
            return Optional.of(InetAddress.getByName(host));
        } catch (UnknownHostException e) {
            LOG.debugv(e, "Could not parse remote address: %s", host);
            return Optional.empty();
        }
    }
}
