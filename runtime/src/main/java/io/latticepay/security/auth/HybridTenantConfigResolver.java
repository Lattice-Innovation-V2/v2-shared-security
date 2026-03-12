package io.latticepay.security.auth;

import io.latticepay.security.config.ActiveProfileSupplier;
import io.latticepay.security.config.GcipConstants;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.latticepay.security.identity.IdentityUtils;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import org.jboss.logging.Logger;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * OIDC multi-tenant resolver that dynamically selects IAP, dev, WIF, or GCIP tenant based on request headers.
 * <p>
 * Tenant selection logic:
 * <ol>
 *   <li>If {@code x-goog-iap-jwt-assertion} header exists → IAP tenant (direct from load balancer, if enabled)</li>
 *   <li>Else if {@code X-Forwarded-IAP-JWT} header exists → IAP tenant (portal-forwarded; Cloud Run strips {@code x-goog-*} on service-to-service calls)</li>
 *   <li>Else if dev tenant enabled and active profile is "dev" and Bearer token present and token {@code iss} matches dev issuer → dev tenant</li>
 *   <li>Else if WIF tenant enabled and Bearer token present and token {@code iss} is {@code https://sts.googleapis.com} → WIF tenant</li>
 *   <li>Else if {@code X-Forwarded-Authorization} or {@code Authorization: Bearer} exists → GCIP tenant (if enabled)</li>
 *   <li>Else → returns null (Quarkus applies default tenant / 401)</li>
 * </ol>
 * <p>
 * Each tenant configuration is lazily built and cached using {@link AtomicReference} for thread-safe initialization.
 */
@ApplicationScoped
public class HybridTenantConfigResolver implements TenantConfigResolver {

    private static final Logger LOG = Logger.getLogger(HybridTenantConfigResolver.class);
    private static final String IAP_HEADER = "x-goog-iap-jwt-assertion";
    /** Portal-forwarded IAP JWT header. Cloud Run strips {@code x-goog-*} reserved headers
     *  on service-to-service calls, so the portal forwards via this non-reserved header. */
    private static final String FORWARDED_IAP_HEADER = "X-Forwarded-IAP-JWT";
    private static final String FORWARDED_AUTH_HEADER = "X-Forwarded-Authorization";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
    private static final String WIF_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
    private static final String IAP_ISSUER = "https://cloud.google.com/iap";
    private static final String CLASSPATH_PREFIX = "classpath:";
    /** One or more Unicode whitespace characters (RFC 6750 BWS). */
    private static final Pattern BWS = Pattern.compile("\\s+");

    private final LatticeSecurityConfig config;
    private final ActiveProfileSupplier activeProfileSupplier;
    private final AtomicReference<OidcTenantConfig> iapConfig = new AtomicReference<>();
    private final AtomicReference<OidcTenantConfig> forwardedIapConfig = new AtomicReference<>();
    private final AtomicReference<OidcTenantConfig> devConfig = new AtomicReference<>();
    private final AtomicReference<OidcTenantConfig> wifConfig = new AtomicReference<>();
    private final AtomicReference<OidcTenantConfig> gcipConfig = new AtomicReference<>();

    public HybridTenantConfigResolver(LatticeSecurityConfig config, Instance<ActiveProfileSupplier> activeProfileSupplierInstance) {
        this.config = config;
        this.activeProfileSupplier = config.dev().enabled()
                ? resolveDevProfileSupplier(activeProfileSupplierInstance)
                : null;
        if (activeProfileSupplier != null) {
            getDevConfig();
        }
    }

    /**
     * Validates that the dev tenant is only used when the active profile is "dev" (bean present), then returns the supplier.
     * When {@code restrictToDevProfile} is false, the profile check is skipped (for sandbox/innovation deployments).
     *
     * @throws IllegalStateException if dev is enabled but not available (production build) or profile restriction is violated
     */
    private ActiveProfileSupplier resolveDevProfileSupplier(Instance<ActiveProfileSupplier> instance) {
        if (instance.isUnsatisfied()) {
            throw new IllegalStateException(
                    "latticepay.security.dev.enabled=true but the dev tenant is not available in production builds. " +
                            "The dev tenant can only be used when running in Quarkus dev mode (quarkus:dev).");
        }
        ActiveProfileSupplier supplier = instance.get();
        boolean restrictToDevProfile = config.dev().restrictToDevProfile();
        if (restrictToDevProfile && !"dev".equals(supplier.getActiveProfile())) {
            throw new IllegalStateException(
                    "latticepay.security.dev.enabled=true is only allowed when the Quarkus profile is 'dev'. " +
                            "Current profile: " + supplier.getActiveProfile() + ". " +
                            "Do not enable the dev tenant in production. " +
                            "If this is a sandbox/innovation deployment, set latticepay.security.dev.restrict-to-dev-profile=false.");
        }
        if (!restrictToDevProfile) {
            LOG.warnv("DEV TENANT ENABLED with restrict-to-dev-profile=false — self-issued JWT tokens will be accepted. " +
                    "Profile: {0}. This is intended for sandbox/innovation deployments only.", supplier.getActiveProfile());
        } else {
            LOG.warnv("DEV TENANT ENABLED - self-issued JWT tokens will be accepted. " +
                    "This must NEVER be active in production. Profile: {0}", supplier.getActiveProfile());
        }
        return supplier;
    }

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext context,
            OidcRequestContext<OidcTenantConfig> requestContext) {

        // 1a. IAP header (direct from load balancer) --> IAP tenant
        if (config.iap().enabled() && hasHeader(context, IAP_HEADER)) {
            LOG.debugv("Selecting IAP tenant (direct)");
            return Uni.createFrom().item(getIapConfig());
        }

        // 1b. Forwarded IAP header (portal-forwarded; Cloud Run strips x-goog-*) --> IAP tenant
        if (config.iap().enabled() && hasHeader(context, FORWARDED_IAP_HEADER)) {
            LOG.debugv("Selecting IAP tenant (forwarded)");
            return Uni.createFrom().item(getForwardedIapConfig());
        }

        // 2. Dev tenant: Bearer present and iss matches dev issuer.
        //    When restrictToDevProfile=true (default), also requires profile == "dev".
        //    When restrictToDevProfile=false, profile check is skipped (sandbox/innovation).
        boolean devProfileOk = !config.dev().restrictToDevProfile()
                || "dev".equals(activeProfileSupplier != null ? activeProfileSupplier.getActiveProfile() : null);
        if (config.dev().enabled() && activeProfileSupplier != null
                && devProfileOk
                && hasBearerToken(context)) {
            Optional<String> bearerValue = getBearerTokenValue(context);
            Optional<String> iss = bearerValue.flatMap(JwtPayloadHelper::getIssuerFromBearerToken);
            if (iss.isPresent() && iss.get().equals(config.dev().issuer().orElse(""))) {
                LOG.debugv("Selecting dev tenant");
                return Uni.createFrom().item(getDevConfig());
            }
        }

        // 3. WIF: Bearer present and iss is sts.googleapis.com
        if (config.wif().enabled() && hasBearerToken(context)) {
            Optional<String> wifIss = getBearerTokenValue(context)
                    .flatMap(JwtPayloadHelper::getIssuerFromBearerToken);
            if (wifIss.isPresent() && IdentityUtils.WIF_ISSUER.equals(wifIss.get())) {
                LOG.debugv("Selecting WIF tenant");
                return Uni.createFrom().item(getWifConfig());
            }
        }

        // 4. Bearer token or forwarded auth --> GCIP tenant
        if (config.gcip().enabled()
                && (hasHeader(context, FORWARDED_AUTH_HEADER) || hasBearerToken(context))) {
            LOG.debugv("Selecting GCIP tenant");
            return Uni.createFrom().item(getGcipConfig());
        }

        // No auth headers --> null (Quarkus returns 401)
        return Uni.createFrom().nullItem();
    }

    private OidcTenantConfig getIapConfig() {
        OidcTenantConfig existing = iapConfig.get();
        if (existing != null) {
            return existing;
        }
        var c = buildIapTenantConfig("iap", IAP_HEADER);
        return iapConfig.compareAndSet(null, c) ? c : iapConfig.get();
    }

    private OidcTenantConfig getForwardedIapConfig() {
        OidcTenantConfig existing = forwardedIapConfig.get();
        if (existing != null) {
            return existing;
        }
        var c = buildIapTenantConfig("iap-forwarded", FORWARDED_IAP_HEADER);
        return forwardedIapConfig.compareAndSet(null, c) ? c : forwardedIapConfig.get();
    }

    /**
     * Builds an IAP tenant config that reads the JWT from the specified header.
     * Both direct IAP ({@code x-goog-iap-jwt-assertion}) and portal-forwarded
     * ({@code X-Forwarded-IAP-JWT}) use identical validation: ES256 signature,
     * same audiences, same issuer — only the token header differs.
     */
    private OidcTenantConfig buildIapTenantConfig(String tenantId, String headerName) {
        String clientId = config.iap().clientId().orElse("");
        if (clientId.isBlank()) {
            throw new IllegalStateException(
                    "latticepay.security.iap.client-id is required for IAP tenant but is missing or blank. " +
                            "Set latticepay.security.iap.client-id (or IAP_CLIENT_ID) to the OAuth2 client ID of your IAP-protected resource so only tokens issued for that audience are accepted.");
        }
        List<String> audiences = new ArrayList<>();
        audiences.add(clientId);
        config.iap().additionalAudiences()
                .map(s -> s.split(","))
                .ifPresent(arr -> {
                    for (String a : arr) {
                        String trimmed = a.trim();
                        if (!trimmed.isEmpty()) audiences.add(trimmed);
                    }
                });
        return OidcTenantConfig.builder()
                .tenantId(tenantId)
                .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE)
                .authServerUrl(IAP_ISSUER)
                .discoveryEnabled(false)
                .jwksPath(IAP_JWKS_URL)
                .token()
                .issuer(IAP_ISSUER)
                .audience(audiences)
                .header(headerName)
                .signatureAlgorithm(io.quarkus.oidc.runtime.OidcTenantConfig.SignatureAlgorithm.ES256)
                .end()
                .build();
    }

    /**
     * Builds and caches the dev tenant config. Eagerly invoked from the constructor when dev is enabled so that
     * {@link #loadPublicKeyContent(String)} runs at startup and the request path never performs blocking I/O.
     */
    private OidcTenantConfig getDevConfig() {
        OidcTenantConfig existing = devConfig.get();
        if (existing != null) {
            return existing;
        }
        String issuer = config.dev().issuer().orElse(null);
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException(
                    "latticepay.security.dev.issuer is required when latticepay.security.dev.enabled=true. " +
                            "Set latticepay.security.dev.issuer (e.g. https://dev.issuer.local).");
        }
        String publicKeyLocation = config.dev().publicKeyLocation().orElse(null);
        if (publicKeyLocation == null || publicKeyLocation.isBlank()) {
            throw new IllegalStateException(
                    "latticepay.security.dev.public-key-location is required when latticepay.security.dev.enabled=true. " +
                            "Set latticepay.security.dev.public-key-location to the path of the PEM public key (e.g. test-publicKey.pem on classpath).");
        }
        String pemContent = loadPublicKeyContent(publicKeyLocation);
        String audience = config.dev().audience();
        if (audience == null || audience.isBlank()) {
            audience = "any";
        }
        var c = OidcTenantConfig.builder()
                .tenantId("dev")
                .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE)
                .discoveryEnabled(false)
                .publicKey(pemContent)
                .token()
                .issuer(issuer)
                .audience(List.of(audience))
                .end()
                .build();
        return devConfig.compareAndSet(null, c) ? c : devConfig.get();
    }

    private String loadPublicKeyContent(String location) {
        validateNoPathTraversal(location);
        String path = resolvePublicKeyPath(location);
        if (location.startsWith(CLASSPATH_PREFIX) || !Paths.get(path).isAbsolute()) {
            return loadPublicKeyFromClasspath(path, location);
        }
        return loadPublicKeyFromFile(location);
    }

    private static void validateNoPathTraversal(String location) {
        if (location.contains("..")) {
            throw new IllegalStateException(
                    "latticepay.security.dev.public-key-location must not contain path traversal (\"..\"): " + location);
        }
    }

    private static String resolvePublicKeyPath(String location) {
        String path = location.startsWith(CLASSPATH_PREFIX)
                ? location.substring(CLASSPATH_PREFIX.length()).trim()
                : location;
        if (path.isEmpty()) {
            throw new IllegalStateException(
                    "latticepay.security.dev.public-key-location is empty or invalid: " + location);
        }
        return path;
    }

    private static String loadPublicKeyFromClasspath(String path, String location) {
        String normalizedClasspathPath = Path.of(path).normalize().toString();
        if (normalizedClasspathPath.startsWith("..") || normalizedClasspathPath.equals("..")) {
            throw new IllegalStateException(
                    "latticepay.security.dev.public-key-location must not resolve outside classpath: " + location);
        }
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(normalizedClasspathPath)) {
            if (in == null) {
                throw new IllegalStateException(
                        "Dev tenant public key not found on classpath: " + normalizedClasspathPath +
                                ". Ensure the PEM file exists (e.g. src/main/resources/" + normalizedClasspathPath + ").");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            if (e instanceof IllegalStateException ise) {
                throw ise;
            }
            throw new IllegalStateException(
                    "Failed to read dev tenant public key from classpath: " + normalizedClasspathPath, e);
        }
    }

    private static String loadPublicKeyFromFile(String location) {
        Path filePath = Path.of(location).normalize();
        try {
            return Files.readString(filePath, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to read dev tenant public key from file: " + location, e);
        }
    }

    private OidcTenantConfig getWifConfig() {
        OidcTenantConfig existing = wifConfig.get();
        if (existing != null) {
            return existing;
        }
        String audience = config.wif().audience().orElse("");
        if (audience.isBlank()) {
            throw new IllegalStateException(
                    "WIF is enabled but audience is not set. " +
                            "Set latticepay.security.wif.audience to the workforce pool provider resource name " +
                            "(e.g. //iam.googleapis.com/locations/global/workforcePools/{pool}/providers/{provider}).");
        }
        String jwksUrl = config.wif().jwksUrl().map(String::trim).filter(s -> !s.isBlank()).orElse(WIF_JWKS_URL);
        var c = OidcTenantConfig.builder()
                .tenantId("wif")
                .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE)
                .authServerUrl(IdentityUtils.WIF_ISSUER)
                .discoveryEnabled(false)
                .jwksPath(jwksUrl)
                .token()
                .issuer(IdentityUtils.WIF_ISSUER)
                .audience(List.of(audience))
                .end()
                .build();
        return wifConfig.compareAndSet(null, c) ? c : wifConfig.get();
    }

    private OidcTenantConfig getGcipConfig() {
        OidcTenantConfig existing = gcipConfig.get();
        if (existing != null) {
            return existing;
        }
        String projectId = config.gcip().projectId().orElse("");
        if (projectId.isBlank() || GcipConstants.MISSING_GCP_PROJECT_ID.equals(projectId)) {
            throw new IllegalStateException(
                    "GCIP is enabled but GCP_PROJECT_ID is not set. Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.");
        }
        String gcipIssuer = "https://securetoken.google.com/" + projectId;
        var c = OidcTenantConfig.builder()
                .tenantId("gcip")
                .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE)
                .authServerUrl(gcipIssuer)
                .token()
                .issuer(gcipIssuer)
                .audience(List.of(projectId))
                .end()
                .build();
        return gcipConfig.compareAndSet(null, c) ? c : gcipConfig.get();
    }

    private boolean hasHeader(RoutingContext ctx, String name) {
        String v = ctx.request().getHeader(name);
        return v != null && !v.isBlank();
    }

    /**
     * Checks for a valid RFC 6750 Bearer token: scheme is case-insensitive, one-or-more whitespace between scheme and token.
     */
    private boolean hasBearerToken(RoutingContext ctx) {
        return getBearerTokenValue(ctx).isPresent();
    }

    /**
     * Parses the Authorization header in an RFC-compliant way: trim header, split on one-or-more Unicode
     * whitespace (RFC 6750 BWS), case-insensitive "bearer" scheme. Returns the token only if non-empty.
     */
    private Optional<String> getBearerTokenValue(RoutingContext ctx) {
        String auth = ctx.request().getHeader(AUTHORIZATION_HEADER);
        if (auth == null) {
            return Optional.empty();
        }
        String trimmed = auth.trim();
        if (trimmed.isEmpty()) {
            return Optional.empty();
        }
        String[] parts = BWS.split(trimmed, 2);
        if (parts.length < 2) {
            return Optional.empty();
        }
        String scheme = parts[0];
        if (!"bearer".equalsIgnoreCase(scheme)) {
            return Optional.empty();
        }
        String token = parts[1].trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }
}
