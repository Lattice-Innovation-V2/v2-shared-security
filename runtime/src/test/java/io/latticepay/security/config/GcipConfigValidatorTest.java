package io.latticepay.security.config;

import io.quarkus.runtime.StartupEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("GcipConfigValidator")
class GcipConfigValidatorTest {

    @Mock
    private LatticeSecurityConfig config;

    @Mock
    private LatticeSecurityConfig.Gcip gcip;

    private void runValidator() {
        var validator = new GcipConfigValidator();
        validator.onStart(new StartupEvent(), config);
    }

    @Nested
    @DisplayName("when GCIP enabled and project-id is MISSING_GCP_PROJECT_ID")
    class WhenGcipEnabledAndProjectIdPlaceholder {

        @Test
        @DisplayName("should throw IllegalStateException with actionable message")
        void shouldThrow() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(true);
            when(gcip.projectId()).thenReturn(Optional.of(GcipConstants.MISSING_GCP_PROJECT_ID));

            IllegalStateException ex = assertThrows(IllegalStateException.class, GcipConfigValidatorTest.this::runValidator);

            assertEquals(
                    "GCIP is enabled but projectId is invalid: projectId must not be null, blank, or equal to GcipConstants.MISSING_GCP_PROJECT_ID (\"" + GcipConstants.MISSING_GCP_PROJECT_ID + "\"). Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.",
                    ex.getMessage());
        }
    }

    @Nested
    @DisplayName("when GCIP enabled and project-id is null, empty, or blank")
    class WhenGcipEnabledAndProjectIdBlank {

        @Test
        @DisplayName("should throw when projectId is null")
        void shouldThrowWhenNull() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(true);
            when(gcip.projectId()).thenReturn(Optional.empty());

            IllegalStateException ex = assertThrows(IllegalStateException.class, GcipConfigValidatorTest.this::runValidator);

            assertEquals(
                    "GCIP is enabled but projectId is invalid: projectId must not be null, blank, or equal to GcipConstants.MISSING_GCP_PROJECT_ID (\"" + GcipConstants.MISSING_GCP_PROJECT_ID + "\"). Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.",
                    ex.getMessage());
        }

        @Test
        @DisplayName("should throw when projectId is empty string")
        void shouldThrowWhenEmpty() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(true);
            when(gcip.projectId()).thenReturn(Optional.of(""));

            IllegalStateException ex = assertThrows(IllegalStateException.class, GcipConfigValidatorTest.this::runValidator);

            assertEquals(
                    "GCIP is enabled but projectId is invalid: projectId must not be null, blank, or equal to GcipConstants.MISSING_GCP_PROJECT_ID (\"" + GcipConstants.MISSING_GCP_PROJECT_ID + "\"). Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.",
                    ex.getMessage());
        }

        @Test
        @DisplayName("should throw when projectId is whitespace-only")
        void shouldThrowWhenWhitespaceOnly() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(true);
            when(gcip.projectId()).thenReturn(Optional.of("   \t "));

            IllegalStateException ex = assertThrows(IllegalStateException.class, GcipConfigValidatorTest.this::runValidator);

            assertEquals(
                    "GCIP is enabled but projectId is invalid: projectId must not be null, blank, or equal to GcipConstants.MISSING_GCP_PROJECT_ID (\"" + GcipConstants.MISSING_GCP_PROJECT_ID + "\"). Set the GCP_PROJECT_ID environment variable or configure latticepay.security.gcip.project-id.",
                    ex.getMessage());
        }
    }

    @Nested
    @DisplayName("when GCIP disabled")
    class WhenGcipDisabled {

        @Test
        @DisplayName("should not throw even if project-id is placeholder")
        void shouldNotThrow() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(false);
            lenient().when(gcip.projectId()).thenReturn(Optional.of(GcipConstants.MISSING_GCP_PROJECT_ID));

            assertDoesNotThrow(GcipConfigValidatorTest.this::runValidator);
        }
    }

    @Nested
    @DisplayName("when GCIP enabled and project-id is set")
    class WhenGcipEnabledAndProjectIdSet {

        @Test
        @DisplayName("should not throw")
        void shouldNotThrow() {
            when(config.gcip()).thenReturn(gcip);
            when(gcip.enabled()).thenReturn(true);
            when(gcip.projectId()).thenReturn(Optional.of("my-gcp-project"));

            assertDoesNotThrow(GcipConfigValidatorTest.this::runValidator);
        }
    }
}
