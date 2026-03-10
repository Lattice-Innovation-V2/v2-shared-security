package io.latticepay.security.config;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/**
 * Validates GCIP configuration at startup so consuming services get fail-fast behavior
 * without duplicating validation logic.
 *
 * When GCIP is enabled, `latticepay.security.gcip.project-id` must be set and non-blank.
 * Startup fails with {@link IllegalStateException} if either of the following holds:
 *
 * <ul>
 *   <li>The {@code projectId} parameter is null, empty, or whitespace-only (missing or blank value).</li>
 *   <li>The {@code projectId} parameter equals {@link GcipConstants#MISSING_GCP_PROJECT_ID}
 *       (e.g. when {@code GCP_PROJECT_ID} is unset and the property defaults to that placeholder).</li>
 * </ul>
 *
 * These are independent validation failures: a null/blank value and the placeholder
 * {@link GcipConstants#MISSING_GCP_PROJECT_ID} are distinct cases.
 *
 * <p>Behavior is aligned with {@link io.latticepay.security.auth.HybridTenantConfigResolver}.
 */
@ApplicationScoped
public class GcipConfigValidator {

    private static final String INVALID_PROJECT_ID_MESSAGE =
            "GCIP is enabled but projectId is invalid: projectId must not be null, blank, or equal to GcipConstants.MISSING_GCP_PROJECT_ID (\"" + GcipConstants.MISSING_GCP_PROJECT_ID + "\"). Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.";

    void onStart(@Observes StartupEvent event, LatticeSecurityConfig config) {
        if (!config.gcip().enabled()) {
            return;
        }
        validate(config.gcip().projectId().orElse(null));
    }

    /**
     * Validates that {@code projectId} is set and not the placeholder.
     * Treats null, blank/empty/whitespace-only, and {@link GcipConstants#MISSING_GCP_PROJECT_ID}
     * the same as invalid, matching {@link io.latticepay.security.auth.HybridTenantConfigResolver} behavior.
     *
     * @param projectId the GCIP project ID (may be null)
     * @throws IllegalStateException if projectId is null, blank, or equals {@link GcipConstants#MISSING_GCP_PROJECT_ID}
     */
    void validate(String projectId) {
        if (projectId == null || projectId.isBlank() || GcipConstants.MISSING_GCP_PROJECT_ID.equals(projectId)) {
            throw new IllegalStateException(INVALID_PROJECT_ID_MESSAGE);
        }
    }
}
