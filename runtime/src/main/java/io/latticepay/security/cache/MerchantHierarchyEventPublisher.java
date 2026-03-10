package io.latticepay.security.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.pubsub.PubSubCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.UUID;

/**
 * Publishes merchant hierarchy events to Redis pub/sub.
 * Used by merchant-service after merchant CRUD operations.
 *
 * No-op when {@code latticepay.security.merchant-hierarchy.publisher-enabled=false}.
 */
@ApplicationScoped
public class MerchantHierarchyEventPublisher {

    private static final Logger LOG = Logger.getLogger(MerchantHierarchyEventPublisher.class);

    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final String channel;
    private final Instance<RedisDataSource> redisInstance;

    public MerchantHierarchyEventPublisher(
            ObjectMapper objectMapper,
            LatticeSecurityConfig config,
            Instance<RedisDataSource> redisInstance) {
        this.objectMapper = objectMapper;
        var mh = config.merchantHierarchy();
        this.enabled = mh.publisherEnabled();
        this.channel = mh.pubsubChannel();
        this.redisInstance = redisInstance;

        if (enabled && !redisInstance.isResolvable()) {
            throw new IllegalStateException(
                    "latticepay.security.merchant-hierarchy.publisher-enabled=true but Redis is not available. "
                            + "Add quarkus-redis-client and configure quarkus.redis.hosts.");
        }
    }

    public void publishMerchantCreated(UUID merchantId, UUID integratorId) {
        publish(new MerchantHierarchyEvent(
                MerchantHierarchyEvent.EventType.MERCHANT_CREATED,
                merchantId, integratorId, null, Instant.now()));
    }

    public void publishMerchantDeleted(UUID merchantId, UUID integratorId) {
        publish(new MerchantHierarchyEvent(
                MerchantHierarchyEvent.EventType.MERCHANT_DELETED,
                merchantId, integratorId, null, Instant.now()));
    }

    public void publishMerchantIntegratorChanged(UUID merchantId, UUID newIntegratorId, UUID previousIntegratorId) {
        publish(new MerchantHierarchyEvent(
                MerchantHierarchyEvent.EventType.MERCHANT_INTEGRATOR_CHANGED,
                merchantId, newIntegratorId, previousIntegratorId, Instant.now()));
    }

    private void publish(MerchantHierarchyEvent event) {
        if (!enabled) {
            return;
        }
        try {
            String json = objectMapper.writeValueAsString(event);
            PubSubCommands<String> pubsub = redisInstance.get().pubsub(String.class);
            pubsub.publish(channel, json);
            LOG.debugf("Published %s event for merchant %s (integrator %s)",
                    event.type(), event.merchantId(), event.integratorId());
        } catch (JsonProcessingException e) {
            LOG.errorf(e, "Failed to serialize merchant hierarchy event: %s", event);
        } catch (Exception e) {
            LOG.warnf(e, "Failed to publish merchant hierarchy event (Redis unavailable?): %s", event.type());
        }
    }
}
