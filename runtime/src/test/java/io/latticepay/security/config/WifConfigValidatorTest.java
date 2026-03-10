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
@DisplayName("WifConfigValidator")
class WifConfigValidatorTest {

    @Mock
    private LatticeSecurityConfig config;

    @Mock
    private LatticeSecurityConfig.Wif wif;

    private void runValidator() {
        var validator = new WifConfigValidator();
        validator.onStart(new StartupEvent(), config);
    }

    @Nested
    @DisplayName("when WIF disabled")
    class WhenWifDisabled {

        @Test
        @DisplayName("should not throw even if audience and poolId are missing")
        void shouldNotThrow() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(false);
            lenient().when(wif.audience()).thenReturn(Optional.empty());
            lenient().when(wif.poolId()).thenReturn(Optional.empty());

            assertDoesNotThrow(WifConfigValidatorTest.this::runValidator);
        }
    }

    @Nested
    @DisplayName("when WIF enabled and properly configured")
    class WhenWifEnabledAndValid {

        @Test
        @DisplayName("should not throw when audience and poolId are set")
        void shouldNotThrow() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(true);
            when(wif.audience()).thenReturn(Optional.of(
                    "//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/my-provider"));
            when(wif.poolId()).thenReturn(Optional.of("my-pool"));

            assertDoesNotThrow(WifConfigValidatorTest.this::runValidator);
        }
    }

    @Nested
    @DisplayName("when WIF enabled but audience missing")
    class WhenWifEnabledAndAudienceMissing {

        @Test
        @DisplayName("should throw when audience is empty Optional")
        void shouldThrow_whenAudienceEmpty() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(true);
            when(wif.audience()).thenReturn(Optional.empty());

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    WifConfigValidatorTest.this::runValidator);

            assertEquals(WifConfigValidator.INVALID_AUDIENCE_MESSAGE, ex.getMessage());
        }

        @Test
        @DisplayName("should throw when audience is blank")
        void shouldThrow_whenAudienceBlank() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(true);
            when(wif.audience()).thenReturn(Optional.of("   "));

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    WifConfigValidatorTest.this::runValidator);

            assertEquals(WifConfigValidator.INVALID_AUDIENCE_MESSAGE, ex.getMessage());
        }
    }

    @Nested
    @DisplayName("when WIF enabled but poolId missing")
    class WhenWifEnabledAndPoolIdMissing {

        @Test
        @DisplayName("should throw when poolId is empty Optional")
        void shouldThrow_whenPoolIdEmpty() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(true);
            when(wif.audience()).thenReturn(Optional.of(
                    "//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/my-provider"));
            when(wif.poolId()).thenReturn(Optional.empty());

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    WifConfigValidatorTest.this::runValidator);

            assertEquals(WifConfigValidator.INVALID_POOL_ID_MESSAGE, ex.getMessage());
        }

        @Test
        @DisplayName("should throw when poolId is blank")
        void shouldThrow_whenPoolIdBlank() {
            when(config.wif()).thenReturn(wif);
            when(wif.enabled()).thenReturn(true);
            when(wif.audience()).thenReturn(Optional.of(
                    "//iam.googleapis.com/locations/global/workforcePools/my-pool/providers/my-provider"));
            when(wif.poolId()).thenReturn(Optional.of("  "));

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    WifConfigValidatorTest.this::runValidator);

            assertEquals(WifConfigValidator.INVALID_POOL_ID_MESSAGE, ex.getMessage());
        }
    }
}
