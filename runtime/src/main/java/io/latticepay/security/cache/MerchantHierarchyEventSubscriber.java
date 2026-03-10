package io.latticepay.security.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.ReactiveRedisDataSource;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.mutiny.subscription.Cancellable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import org.jboss.logging.Logger;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Subscribes to merchant hierarchy events via Redis pub/sub.
 * Dispatches events to {@link MerchantHierarchyEventHandler} SPI implementations.
 *
 * No-op when {@code latticepay.security.merchant-hierarchy.subscriber-enabled=false}.
 */
@ApplicationScoped
public class MerchantHierarchyEventSubscriber {

    private static final Logger LOG = Logger.getLogger(MerchantHierarchyEventSubscriber.class);

    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final String channel;
    private final Instance<ReactiveRedisDataSource> reactiveRedisInstance;
    private final Instance<MerchantHierarchyEventHandler> handlerInstance;

    private final AtomicReference<Cancellable> subscription = new AtomicReference<>();

    public MerchantHierarchyEventSubscriber(
            ObjectMapper objectMapper,
            LatticeSecurityConfig config,
            Instance<ReactiveRedisDataSource> reactiveRedisInstance,
            Instance<MerchantHierarchyEventHandler> handlerInstance) {
        this.objectMapper = objectMapper;
        var mh = config.merchantHierarchy();
        this.enabled = mh.subscriberEnabled();
        this.channel = mh.pubsubChannel();
        this.reactiveRedisInstance = reactiveRedisInstance;
        this.handlerInstance = handlerInstance;
    }

    void onStart(@Observes StartupEvent event) {
        if (!enabled) {
            LOG.debug("Merchant hierarchy event subscriber disabled");
            return;
        }
        if (!reactiveRedisInstance.isResolvable()) {
            LOG.warn("Merchant hierarchy subscriber enabled but ReactiveRedisDataSource not available");
            return;
        }
        if (!handlerInstance.isResolvable()) {
            LOG.warn("Merchant hierarchy subscriber enabled but no MerchantHierarchyEventHandler found");
            return;
        }

        try {
            var pubsub = reactiveRedisInstance.get().pubsub(String.class);

            subscription.set(pubsub.subscribe(channel)
                    .emitOn(runnable -> Thread.ofVirtual().name("merchant-event-handler").start(runnable))
                    .subscribe().with(
                            this::handleMessage,
                            throwable -> LOG.errorf(throwable,
                                    "Merchant hierarchy subscription error on channel %s", channel)
                    ));

            LOG.infof("Subscribed to merchant hierarchy events on channel: %s", channel);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to subscribe to merchant hierarchy events on channel: %s", channel);
        }
    }

    void onShutdown(@Observes ShutdownEvent event) {
        Cancellable current = subscription.getAndSet(null);
        if (current != null) {
            current.cancel();
            LOG.info("Unsubscribed from merchant hierarchy events");
        }
    }

    private void handleMessage(String json) {
        try {
            MerchantHierarchyEvent event = objectMapper.readValue(json, MerchantHierarchyEvent.class);
            MerchantHierarchyEventHandler handler = handlerInstance.get();

            switch (event.type()) {
                case MERCHANT_CREATED -> handler.onMerchantCreated(event);
                case MERCHANT_DELETED -> handler.onMerchantDeleted(event);
                case MERCHANT_INTEGRATOR_CHANGED -> handler.onMerchantIntegratorChanged(event);
                default -> {
                    LOG.warnf("Unknown merchant hierarchy event type: type=%s, merchantId=%s, rawJson=%s",
                            event.type(), event.merchantId(), json);
                    handler.onUnknownEvent(event, json);
                    return;
                }
            }

            LOG.debugf("Handled %s event for merchant %s (integrator %s)",
                    event.type(), event.merchantId(), event.integratorId());
        } catch (JsonProcessingException e) {
            LOG.errorf(e, "Failed to deserialize merchant hierarchy event: %s", json);
        } catch (Exception e) {
            LOG.errorf(e, "Error handling merchant hierarchy event: %s", json);
        }
    }
}
