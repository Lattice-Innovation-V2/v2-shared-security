package io.latticepay.security.config;

import org.eclipse.microprofile.config.ConfigProvider;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Supplies the active Quarkus profile at runtime (e.g. "dev", "prod", "test").
 * Used to guard dev-only features so they cannot run in production.
 */
@ApplicationScoped
public class ActiveProfileSupplier {

    private static final String QUARKUS_PROFILE_KEY = "quarkus.profile";
    private static final String DEFAULT_PROFILE = "prod";

    /**
     * Returns the active Quarkus profile.
     *
     * @return the profile name (e.g. "dev", "prod"); never null
     */
    public String getActiveProfile() {
        return ConfigProvider.getConfig()
                .getOptionalValue(QUARKUS_PROFILE_KEY, String.class)
                .orElse(DEFAULT_PROFILE);
    }
}
