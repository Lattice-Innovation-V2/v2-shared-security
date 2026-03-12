package io.latticepay.security.deployment;

import io.latticepay.security.auth.ForwardedAuthFilter;
import io.latticepay.security.auth.HybridTenantConfigResolver;
import io.latticepay.security.cache.MerchantHierarchyEvent;
import io.latticepay.security.cache.MerchantHierarchyEventPublisher;
import io.latticepay.security.cache.MerchantHierarchyEventSubscriber;
import io.latticepay.security.config.ActiveProfileSupplier;
import io.latticepay.security.config.GcipConfigValidator;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.latticepay.security.config.WifConfigValidator;
import io.latticepay.security.gcp.DefaultGcpTokenProvider;
import io.latticepay.security.gcp.GcpIamClientFilter;
import io.latticepay.security.identity.CallerScopeAuditFilter;
import io.latticepay.security.identity.CallerScopeResolvingFilter;
import io.latticepay.security.identity.HierarchyResolver;
import io.latticepay.security.identity.IdentityUtils;
import io.latticepay.security.identity.MerchantHierarchyCache;
import io.latticepay.security.identity.LatticeRolesAugmentor;
import io.latticepay.security.identity.RequestCallerScope;
import io.latticepay.security.swagger.InternalOnlyFilter;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.ConfigMappingBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;

/**
 * Build-time processor for Latticepay Security extension.
 *
 * Registers all CDI beans from the runtime module so they are automatically discovered
 * by consuming Quarkus applications.
 */
class LatticeSecurityProcessor {

    private static final String FEATURE = "latticepay-security";
    private static final String CONFIG_PREFIX = "latticepay.security";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    AdditionalBeanBuildItem registerBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        ForwardedAuthFilter.class,
                        GcipConfigValidator.class,
                        WifConfigValidator.class,
                        HybridTenantConfigResolver.class,
                        IdentityUtils.class,
                        LatticeRolesAugmentor.class,
                        HierarchyResolver.class,
                        MerchantHierarchyCache.class,
                        DefaultGcpTokenProvider.class,
                        GcpIamClientFilter.class,
                        InternalOnlyFilter.class,
                        MerchantHierarchyEventPublisher.class,
                        MerchantHierarchyEventSubscriber.class,
                        RequestCallerScope.class,
                        CallerScopeResolvingFilter.class,
                        CallerScopeAuditFilter.class)
                .setUnremovable()
                .build();
    }

    /**
     * Registers dev-tenant support beans in ALL launch modes.
     * The runtime guard ({@code latticepay.security.dev.restrict-to-dev-profile}, default true)
     * prevents the dev tenant from being used outside the "dev" profile unless explicitly opted out.
     * The bean must always be available so the runtime can read the active profile and make
     * the decision (rather than failing at build time for sandbox/innovation deployments).
     */
    @BuildStep
    AdditionalBeanBuildItem registerDevBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(ActiveProfileSupplier.class)
                .setUnremovable()
                .build();
    }

    /**
     * Register LatticeSecurityConfig as a config mapping.
     *
     * This is REQUIRED for Quarkus extensions that define {@code @ConfigMapping} interfaces.
     * Without this build step, consuming applications will fail with:
     * "Could not find a mapping for io.latticepay.security.config.LatticeSecurityConfig"
     *
     * The ConfigMappingBuildItem tells Quarkus to register this interface as a configuration
     * mapping at build time, making it available for CDI injection in consuming applications.
     */
    @BuildStep
    void registerConfigMapping(io.quarkus.deployment.annotations.BuildProducer<ConfigMappingBuildItem> configMapping) {
        configMapping.produce(new ConfigMappingBuildItem(LatticeSecurityConfig.class, CONFIG_PREFIX));
    }

    /**
     * Register config mapping classes for reflection (required for native image).
     * This ensures LatticeSecurityConfig and its nested interfaces are accessible
     * via reflection in GraalVM native images.
     */
    @BuildStep
    ReflectiveClassBuildItem registerConfigForReflection() {
        return ReflectiveClassBuildItem.builder(
                        LatticeSecurityConfig.class,
                        LatticeSecurityConfig.ForwardedAuth.class,
                        LatticeSecurityConfig.Iap.class,
                        LatticeSecurityConfig.Gcip.class,
                        LatticeSecurityConfig.Dev.class,
                        LatticeSecurityConfig.Wif.class,
                        LatticeSecurityConfig.GcpServiceAuth.class,
                        LatticeSecurityConfig.SwaggerProtection.class,
                        LatticeSecurityConfig.MerchantHierarchy.class,
                        io.latticepay.security.identity.CallerScope.class,
                        io.latticepay.security.identity.CallerScope.AuthProvider.class,
                        MerchantHierarchyEvent.class,
                        MerchantHierarchyEvent.EventType.class)
                .methods()
                .build();
    }

}
