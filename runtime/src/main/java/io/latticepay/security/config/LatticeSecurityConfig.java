package io.latticepay.security.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

import java.time.Duration;
import java.util.Optional;

/**
 * Unified configuration interface for Latticepay Security library.
 *
 * All security-related configuration is grouped under the {@code latticepay.security} prefix.
 * Each authentication flow (IAP, GCIP) has an explicit {@code enabled} flag for opt-in control.
 */
@ConfigMapping(prefix = "latticepay.security")
public interface LatticeSecurityConfig {

    /**
     * Internal user email domain suffix (e.g. "@latticepay.io").
     * Users with emails ending in this domain are considered internal/admin users.
     */
    @WithDefault("@latticepay.io")
    String internalDomain();

    /**
     * Custom JWT claim name for role.
     * GCIP tokens carry an authoritative {@code role} claim set during user provisioning.
     * IAP tokens do not use this claim (internal users are assigned "admin" by the augmentor).
     */
    @WithDefault("role")
    String roleClaim();

    /**
     * Forwarded-auth proxy filter settings.
     * Controls copying {@code X-Forwarded-Authorization} to {@code Authorization} header.
     */
    ForwardedAuth forwardedAuth();

    /**
     * IAP (Identity-Aware Proxy) tenant settings.
     * For internal Google Workspace users accessing admin portals.
     */
    Iap iap();

    /**
     * GCIP/Firebase (Google Cloud Identity Platform) tenant settings.
     * For external customers accessing public APIs.
     */
    Gcip gcip();

    /**
     * GCP IAM outbound client filter settings (service-to-service).
     * Controls attaching GCP IAM identity tokens to outbound REST client requests.
     */
    GcpServiceAuth gcpServiceAuth();

    /**
     * Swagger-UI protection settings.
     * Controls access to Swagger-UI and OpenAPI documentation endpoints.
     */
    SwaggerProtection swaggerProtection();

    /** 
     * Merchant hierarchy cache settings.
     * When enabled, {@link io.latticepay.security.identity.HierarchyResolver#resolveAccessibleMerchantIds}
     * uses Redis for caching integrator-to-merchant mappings. Requires {@code quarkus-redis-client}
     * and a {@link io.latticepay.security.identity.MerchantAccessResolver} implementation.
     */
    MerchantHierarchy merchantHierarchy();
    /**
    * Dev tenant settings (self-issued JWT for local development).
     * When enabled, Bearer tokens whose {@code iss} claim matches the configured dev issuer
     * are validated using a local public key (no OIDC discovery). Intended for %dev only.
     */
    Dev dev();

    /**
     * WIF (Workforce Identity Federation) tenant settings.
     * For external customers using STS token exchange to obtain GCP WIF tokens.
     * When enabled, Bearer tokens with {@code iss=https://sts.googleapis.com} are validated
     * as WIF tokens using a static JWKS endpoint (no OIDC discovery).
     */
    Wif wif();

    /**
     * Forwarded-auth proxy filter configuration.
     */
    interface ForwardedAuth {
        /**
         * Enable the forwarded-auth filter.
         * When enabled, {@code X-Forwarded-Authorization} is copied to {@code Authorization}
         * only from trusted sources (see {@link #trustedProxyIps()}).
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Comma-separated list of trusted proxy IP addresses.
         * - Empty or "NONE" = no trusted IPs (filter disabled even if enabled=true)
         * - Non-empty = only these IPs may send {@code X-Forwarded-Authorization}
         * - If enabled=true and this is empty, all sources are trusted (use only when
         *   the service is exclusively reached via a gateway that strips the header)
         */
        @WithDefault("NONE")
        String trustedProxyIps();
    }

    /**
     * IAP (admin portal) tenant configuration.
     */
    interface Iap {
        /**
         * Enable IAP tenant.
         * When enabled, requests with {@code x-goog-iap-jwt-assertion} header are validated
         * as IAP tokens.
         */
        @WithDefault("true")
        boolean enabled();

        /**
         * OAuth2 client ID for the IAP-protected resource.
         * Required when {@link #enabled()} is true.
         * This is the audience that IAP tokens must match.
         */
        Optional<String> clientId();

        /**
         * Additional audiences accepted by the IAP tenant (comma-separated).
         * Allows accepting IAP JWTs issued for other backends (e.g., the portal
         * forwards its IAP JWT to this service with a different audience).
         */
        Optional<String> additionalAudiences();
    }

    /**
     * GCIP/Firebase (external customer) tenant configuration.
     */
    interface Gcip {
        /**
         * Enable GCIP tenant.
         * When enabled, requests with {@code Authorization: Bearer} header are validated
         * as GCIP/Firebase tokens.
         */
        @WithDefault("true")
        boolean enabled();

        /**
         * GCP/Firebase project ID for GCIP tenant.
         * Required when {@link #enabled()} is true.
         * Used to build the issuer URL: {@code https://securetoken.google.com/{project-id}}
         */
        Optional<String> projectId();

        /**
         * Prefix pattern for integrator tenant IDs in GCIP.
         * Tenant IDs matching this prefix are treated as integrator tenants.
         * Example: "integrator-" matches "integrator-int_abc123".
         */
        @WithDefault("integrator-")
        String integratorTenantPrefix();

        /**
         * Prefix pattern for merchant tenant IDs in GCIP.
         * Tenant IDs matching this prefix are treated as merchant tenants.
         * Example: "merchant-" matches "merchant-int_abc123".
         */
        @WithDefault("merchant-")
        String merchantTenantPrefix();
    }

    /**
     * GCP IAM outbound client filter configuration (service-to-service).
     */
    interface GcpServiceAuth {
        /**
         * Enable outbound GCP IAM auth filter.
         * When enabled, the {@link io.latticepay.security.gcp.GcpIamClientFilter} attaches
         * GCP IAM identity tokens to outbound REST client requests.
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Target audience for outbound identity tokens.
         * Required when {@link #enabled()} is true.
         * This is typically the URL of the downstream service (e.g., {@code https://merchant-service}).
         */
        Optional<String> targetAudience();
    }

    /**
     * Dev tenant configuration (self-issued JWT for local development).
     * Required when enabled: {@link #issuer()}, {@link #publicKeyLocation()}.
     */
    interface Dev {
        /**
         * Enable the dev tenant.
         * When enabled, Bearer tokens with {@code iss} equal to {@link #issuer()} are
         * validated using the key at {@link #publicKeyLocation()} (no OIDC discovery).
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Issuer value that must match the JWT {@code iss} claim (e.g. {@code https://dev.issuer.local}).
         * Required when {@link #enabled()} is true.
         */
        Optional<String> issuer();

        /**
         * Location of the PEM public key for verifying dev tokens.
         * Use a classpath-relative path (e.g. {@code test-publicKey.pem}) or prefix with
         * {@code classpath:}; use an absolute path for a file. Required when {@link #enabled()} is true.
         */
        Optional<String> publicKeyLocation();

        /**
         * Audience(s) to accept for dev tokens (default {@code any} to match common dev tools).
         */
        @WithDefault("any")
        String audience();

        /**
         * When true (default), the dev tenant is only allowed when the Quarkus profile is "dev".
         * Set to false for sandbox/innovation deployments that use prod infrastructure
         * but need dev JWT verification (e.g. V2 sandbox without real IAP).
         */
        @WithDefault("true")
        boolean restrictToDevProfile();
    }

    /**
     * Swagger-UI protection configuration.
     * Controls access to Swagger-UI and OpenAPI documentation endpoints.
     */
    interface SwaggerProtection {
        /**
         * Enable Swagger-UI protection filter.
         * When enabled, the {@link io.latticepay.security.swagger.InternalOnlyFilter} restricts
         * access to {@code /q/docs} and {@code /q/openapi} endpoints to internal users only
         * (users with {@literal @}latticepay.io email domain).
         *
         * External users will receive HTTP 403 Forbidden when attempting to access documentation.
         *
         * **Default:** true (protection enabled)
         *
         * **Security Note:** Disabling this exposes API documentation to external users.
         * Only disable in development environments or if you have alternative access controls in place.
         */
        @WithDefault("true")
        boolean enabled();
    }

    /**
     * WIF (Workforce Identity Federation) tenant configuration.
     * For external customers who exchange their own JWTs for GCP WIF tokens via STS.
     */
    interface Wif {
        /**
         * Enable WIF tenant.
         * When enabled, Bearer tokens with {@code iss=https://sts.googleapis.com} are
         * validated as WIF tokens using a static JWKS endpoint (no OIDC discovery).
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Expected audience for WIF tokens.
         * Format: {@code //iam.googleapis.com/locations/global/workforcePools/{pool-id}/providers/{provider-id}}
         * Required when {@link #enabled()} is true.
         */
        Optional<String> audience();

        /**
         * Workforce pool ID (e.g. "latticepay-integrator-pool").
         * Required when {@link #enabled()} is true.
         */
        Optional<String> poolId();

        /**
         * JWKS endpoint URL for verifying WIF token signatures.
         * Google STS ({@code https://sts.googleapis.com}) does not expose an OIDC discovery
         * endpoint, so the JWKS URL must be configured explicitly.
         * Defaults to Google's public OAuth2 JWKS ({@code https://www.googleapis.com/oauth2/v3/certs}).
         */
        Optional<String> jwksUrl();

        /**
         * Provider ID prefix for extracting integrator context from WIF audience.
         * The provider ID is parsed from the audience URI and this prefix is stripped
         * to obtain the integrator identifier.
         */
        @WithDefault("provider-integrator-")
        String providerPrefix();
    }

    /**
     * Merchant hierarchy cache configuration.
     */
    interface MerchantHierarchy {
        /**
         * Enable Redis-backed merchant hierarchy cache.
         * When enabled, integrator-to-merchant resolution uses Redis with SPI fallback on miss.
         * Requires {@code quarkus-redis-client} on the classpath and {@code quarkus.redis.hosts}
         * configured.
         */
        @WithDefault("false")
        boolean enabled();

        /**
         * Redis key prefix for hierarchy cache entries.
         * Keys are formatted as {@code {prefix}:{integratorId}:merchants}.
         */
        @WithDefault("latticepay:hierarchy")
        String redisKeyPrefix();

        /**
         * TTL for cache entries (ISO-8601 duration).
         */
        @WithDefault("PT1H")
        Duration ttl();

        /**
         * Redis pub/sub channel for merchant hierarchy events.
         */
        @WithDefault("latticepay:merchant-hierarchy:events")
        String pubsubChannel();

        /**
         * Enable pub/sub event publishing (for merchant-service).
         * When enabled, {@link io.latticepay.security.cache.MerchantHierarchyEventPublisher}
         * publishes events after merchant CRUD operations.
         */
        @WithDefault("false")
        boolean publisherEnabled();

        /**
         * Enable pub/sub event subscribing (for integrator-service).
         * When enabled, {@link io.latticepay.security.cache.MerchantHierarchyEventSubscriber}
         * listens for merchant events and dispatches to
         * {@link io.latticepay.security.cache.MerchantHierarchyEventHandler} implementations.
         */
        @WithDefault("false")
        boolean subscriberEnabled();
    }
}
