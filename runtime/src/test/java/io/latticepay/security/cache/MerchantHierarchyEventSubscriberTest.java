package io.latticepay.security.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.ReactiveRedisDataSource;
import io.quarkus.redis.datasource.pubsub.ReactivePubSubCommands;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.mutiny.Multi;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.*;

@DisplayName("MerchantHierarchyEventSubscriber")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MerchantHierarchyEventSubscriberTest {

    @Mock
    private LatticeSecurityConfig config;
    @Mock
    private LatticeSecurityConfig.MerchantHierarchy merchantHierarchyConfig;
    @Mock
    private Instance<ReactiveRedisDataSource> reactiveRedisInstance;
    @Mock
    private ReactiveRedisDataSource reactiveRedisDataSource;
    @Mock
    @SuppressWarnings("unchecked")
    private ReactivePubSubCommands<String> reactivePubSubCommands;
    @Mock
    private Instance<MerchantHierarchyEventHandler> handlerInstance;
    @Mock
    private MerchantHierarchyEventHandler handler;

    private static final String CHANNEL = "latticepay:merchant-hierarchy:events";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    @BeforeEach
    void setUp() {
        when(config.merchantHierarchy()).thenReturn(merchantHierarchyConfig);
        when(merchantHierarchyConfig.pubsubChannel()).thenReturn(CHANNEL);
        lenient().when(reactiveRedisInstance.isResolvable()).thenReturn(true);
        lenient().when(reactiveRedisInstance.get()).thenReturn(reactiveRedisDataSource);
        lenient().when(reactiveRedisDataSource.pubsub(String.class)).thenReturn(reactivePubSubCommands);
        lenient().when(handlerInstance.isResolvable()).thenReturn(true);
        lenient().when(handlerInstance.get()).thenReturn(handler);
    }

    @Nested
    @DisplayName("onStart")
    class OnStart {

        @Test
        @DisplayName("does not subscribe when disabled")
        void doesNotSubscribe_whenDisabled() {
            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(false);
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());

            verifyNoInteractions(reactiveRedisInstance);
        }

        @Test
        @DisplayName("does not subscribe when Redis not available")
        void doesNotSubscribe_whenRedisNotAvailable() {
            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactiveRedisInstance.isResolvable()).thenReturn(false);
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());

            verify(reactiveRedisInstance, never()).get();
        }

        @Test
        @DisplayName("does not subscribe when no handler available")
        void doesNotSubscribe_whenNoHandlerAvailable() {
            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(handlerInstance.isResolvable()).thenReturn(false);
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());

            verify(reactiveRedisInstance, never()).get();
        }

        @Test
        @DisplayName("subscribes to channel when enabled")
        void subscribesToChannel_whenEnabled() {
            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactivePubSubCommands.subscribe(CHANNEL)).thenReturn(Multi.createFrom().empty());
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());

            verify(reactivePubSubCommands).subscribe(CHANNEL);
        }
    }

    @Nested
    @DisplayName("message dispatch")
    class MessageDispatch {

        @Test
        @DisplayName("dispatches MERCHANT_CREATED to handler")
        void dispatchesMerchantCreated() throws Exception {
            UUID merchantId = UUID.randomUUID();
            UUID integratorId = UUID.randomUUID();
            var event = new MerchantHierarchyEvent(
                    MerchantHierarchyEvent.EventType.MERCHANT_CREATED,
                    merchantId, integratorId, null, Instant.now());
            String json = OBJECT_MAPPER.writeValueAsString(event);

            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactivePubSubCommands.subscribe(CHANNEL))
                    .thenReturn(Multi.createFrom().item(json));
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());
            Thread.sleep(200);

            verify(handler).onMerchantCreated(argThat(e ->
                    e.type() == MerchantHierarchyEvent.EventType.MERCHANT_CREATED
                            && e.merchantId().equals(merchantId)
                            && e.integratorId().equals(integratorId)));
        }

        @Test
        @DisplayName("dispatches MERCHANT_DELETED to handler")
        void dispatchesMerchantDeleted() throws Exception {
            UUID merchantId = UUID.randomUUID();
            UUID integratorId = UUID.randomUUID();
            var event = new MerchantHierarchyEvent(
                    MerchantHierarchyEvent.EventType.MERCHANT_DELETED,
                    merchantId, integratorId, null, Instant.now());
            String json = OBJECT_MAPPER.writeValueAsString(event);

            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactivePubSubCommands.subscribe(CHANNEL))
                    .thenReturn(Multi.createFrom().item(json));
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());
            Thread.sleep(200);

            verify(handler).onMerchantDeleted(argThat(e ->
                    e.type() == MerchantHierarchyEvent.EventType.MERCHANT_DELETED
                            && e.merchantId().equals(merchantId)));
        }

        @Test
        @DisplayName("dispatches MERCHANT_INTEGRATOR_CHANGED to handler")
        void dispatchesMerchantIntegratorChanged() throws Exception {
            UUID merchantId = UUID.randomUUID();
            UUID integratorId = UUID.randomUUID();
            UUID previousIntegratorId = UUID.randomUUID();
            var event = new MerchantHierarchyEvent(
                    MerchantHierarchyEvent.EventType.MERCHANT_INTEGRATOR_CHANGED,
                    merchantId, integratorId, previousIntegratorId, Instant.now());
            String json = OBJECT_MAPPER.writeValueAsString(event);

            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactivePubSubCommands.subscribe(CHANNEL))
                    .thenReturn(Multi.createFrom().item(json));
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());
            Thread.sleep(200);

            verify(handler).onMerchantIntegratorChanged(argThat(e ->
                    e.type() == MerchantHierarchyEvent.EventType.MERCHANT_INTEGRATOR_CHANGED
                            && e.previousIntegratorId().equals(previousIntegratorId)));
        }

        @Test
        @DisplayName("handles invalid JSON without crashing")
        void handlesInvalidJson() throws Exception {
            when(merchantHierarchyConfig.subscriberEnabled()).thenReturn(true);
            when(reactivePubSubCommands.subscribe(CHANNEL))
                    .thenReturn(Multi.createFrom().item("not-valid-json"));
            var subscriber = new MerchantHierarchyEventSubscriber(OBJECT_MAPPER, config, reactiveRedisInstance, handlerInstance);

            subscriber.onStart(new StartupEvent());
            Thread.sleep(200);

            verifyNoInteractions(handler);
        }
    }
}
