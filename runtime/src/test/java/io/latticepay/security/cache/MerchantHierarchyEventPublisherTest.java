package io.latticepay.security.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.pubsub.PubSubCommands;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@DisplayName("MerchantHierarchyEventPublisher")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MerchantHierarchyEventPublisherTest {

    @Mock
    private LatticeSecurityConfig config;
    @Mock
    private LatticeSecurityConfig.MerchantHierarchy merchantHierarchyConfig;
    @Mock
    private Instance<RedisDataSource> redisInstance;
    @Mock
    private RedisDataSource redisDataSource;
    @Mock
    @SuppressWarnings("unchecked")
    private PubSubCommands<String> pubSubCommands;

    private static final String CHANNEL = "latticepay:merchant-hierarchy:events";
    private static final UUID MERCHANT_ID = UUID.randomUUID();
    private static final UUID INTEGRATOR_ID = UUID.randomUUID();
    private static final UUID PREVIOUS_INTEGRATOR_ID = UUID.randomUUID();

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @BeforeEach
    void setUp() {
        when(config.merchantHierarchy()).thenReturn(merchantHierarchyConfig);
        when(merchantHierarchyConfig.pubsubChannel()).thenReturn(CHANNEL);
        lenient().when(redisInstance.isResolvable()).thenReturn(true);
        lenient().when(redisInstance.get()).thenReturn(redisDataSource);
        lenient().when(redisDataSource.pubsub(String.class)).thenReturn(pubSubCommands);
    }

    @Nested
    @DisplayName("constructor")
    class Constructor {

        @Test
        @DisplayName("throws IllegalStateException when enabled but Redis not available")
        void throwsIllegalStateException_whenEnabledAndRedisNotAvailable() {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(true);
            when(redisInstance.isResolvable()).thenReturn(false);

            assertThrows(IllegalStateException.class,
                    () -> new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance));
        }

        @Test
        @DisplayName("does not throw when disabled and Redis not available")
        void doesNotThrow_whenDisabledAndRedisNotAvailable() {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(false);
            when(redisInstance.isResolvable()).thenReturn(false);

            assertDoesNotThrow(() -> new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance));
        }
    }

    @Nested
    @DisplayName("publishMerchantCreated")
    class PublishMerchantCreated {

        @Test
        @DisplayName("publishes MERCHANT_CREATED event with correct JSON")
        void publishesCreatedEvent() throws Exception {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(true);
            var publisher = new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance);

            publisher.publishMerchantCreated(MERCHANT_ID, INTEGRATOR_ID);

            ArgumentCaptor<String> jsonCaptor = ArgumentCaptor.forClass(String.class);
            verify(pubSubCommands).publish(eq(CHANNEL), jsonCaptor.capture());

            MerchantHierarchyEvent event = OBJECT_MAPPER.readValue(jsonCaptor.getValue(), MerchantHierarchyEvent.class);
            assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_CREATED, event.type());
            assertEquals(MERCHANT_ID, event.merchantId());
            assertEquals(INTEGRATOR_ID, event.integratorId());
            assertNull(event.previousIntegratorId());
            assertNotNull(event.timestamp());
        }

        @Test
        @DisplayName("does nothing when disabled")
        void doesNothing_whenDisabled() {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(false);
            var publisher = new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance);

            publisher.publishMerchantCreated(MERCHANT_ID, INTEGRATOR_ID);

            verifyNoInteractions(redisDataSource);
        }
    }

    @Nested
    @DisplayName("publishMerchantDeleted")
    class PublishMerchantDeleted {

        @Test
        @DisplayName("publishes MERCHANT_DELETED event")
        void publishesDeletedEvent() throws Exception {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(true);
            var publisher = new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance);

            publisher.publishMerchantDeleted(MERCHANT_ID, INTEGRATOR_ID);

            ArgumentCaptor<String> jsonCaptor = ArgumentCaptor.forClass(String.class);
            verify(pubSubCommands).publish(eq(CHANNEL), jsonCaptor.capture());

            MerchantHierarchyEvent event = OBJECT_MAPPER.readValue(jsonCaptor.getValue(), MerchantHierarchyEvent.class);
            assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_DELETED, event.type());
            assertEquals(MERCHANT_ID, event.merchantId());
            assertEquals(INTEGRATOR_ID, event.integratorId());
        }
    }

    @Nested
    @DisplayName("publishMerchantIntegratorChanged")
    class PublishMerchantIntegratorChanged {

        @Test
        @DisplayName("publishes MERCHANT_INTEGRATOR_CHANGED event with previous integrator")
        void publishesIntegratorChangedEvent() throws Exception {
            when(merchantHierarchyConfig.publisherEnabled()).thenReturn(true);
            var publisher = new MerchantHierarchyEventPublisher(OBJECT_MAPPER, config, redisInstance);

            publisher.publishMerchantIntegratorChanged(MERCHANT_ID, INTEGRATOR_ID, PREVIOUS_INTEGRATOR_ID);

            ArgumentCaptor<String> jsonCaptor = ArgumentCaptor.forClass(String.class);
            verify(pubSubCommands).publish(eq(CHANNEL), jsonCaptor.capture());

            MerchantHierarchyEvent event = OBJECT_MAPPER.readValue(jsonCaptor.getValue(), MerchantHierarchyEvent.class);
            assertEquals(MerchantHierarchyEvent.EventType.MERCHANT_INTEGRATOR_CHANGED, event.type());
            assertEquals(MERCHANT_ID, event.merchantId());
            assertEquals(INTEGRATOR_ID, event.integratorId());
            assertEquals(PREVIOUS_INTEGRATOR_ID, event.previousIntegratorId());
        }
    }
}
