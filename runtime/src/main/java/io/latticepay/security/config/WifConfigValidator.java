package io.latticepay.security.config;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * Validates WIF (Workforce Identity Federation) configuration at startup so consuming
 * services get fail-fast behavior without duplicating validation logic.
 *
 * When WIF is enabled, {@code latticepay.security.wif.audience} and
 * {@code latticepay.security.wif.pool-id} must be set and non-blank.
 */
@ApplicationScoped
public class WifConfigValidator {

    static final String INVALID_AUDIENCE_MESSAGE =
            "WIF is enabled but audience is not set. " +
                    "Set latticepay.security.wif.audience to the workforce pool provider resource name " +
                    "(e.g. //iam.googleapis.com/locations/global/workforcePools/{pool}/providers/{provider}).";

    static final String INVALID_POOL_ID_MESSAGE =
            "WIF is enabled but pool-id is not set. " +
                    "Set latticepay.security.wif.pool-id to the workforce pool ID " +
                    "(e.g. latticepay-integrator-pool).";

    void onStart(@Observes StartupEvent event, LatticeSecurityConfig config) {
        if (!config.wif().enabled()) {
            return;
        }
        var wif = config.wif();
        if (wif.audience().isEmpty() || wif.audience().orElse("").isBlank()) {
            throw new IllegalStateException(INVALID_AUDIENCE_MESSAGE);
        }
        if (wif.poolId().isEmpty() || wif.poolId().orElse("").isBlank()) {
            throw new IllegalStateException(INVALID_POOL_ID_MESSAGE);
        }
    }
}
