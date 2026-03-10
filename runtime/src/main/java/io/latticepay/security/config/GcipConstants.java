package io.latticepay.security.config;

/**
 * Constants for GCIP (Google Cloud Identity Platform) configuration.
 * <p>
 * Use {@link #MISSING_GCP_PROJECT_ID} as the default value in {@code application.properties}
 * when reading from the environment, e.g. {@code latticepay.security.gcip.project-id=${GCP_PROJECT_ID:MISSING_GCP_PROJECT_ID}}.
 * The extension validates at startup and fails fast if GCIP is enabled and this placeholder is still present.
 */
public final class GcipConstants {

    /**
     * Placeholder value indicating that {@code GCP_PROJECT_ID} was not set.
     * When GCIP is enabled and {@code latticepay.security.gcip.project-id} resolves to this value,
     * the extension throws at startup with an actionable message.
     */
    public static final String MISSING_GCP_PROJECT_ID = "MISSING_GCP_PROJECT_ID";

    private GcipConstants() {}
}
