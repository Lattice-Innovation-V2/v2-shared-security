package io.latticepay.security.identity;

import io.latticepay.security.config.LatticeSecurityConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.transactions.TransactionalRedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.keys.TransactionalKeyCommands;
import io.quarkus.redis.datasource.set.SetCommands;
import io.quarkus.redis.datasource.set.TransactionalSetCommands;
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

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@DisplayName("MerchantHierarchyCache")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MerchantHierarchyCacheTest {

    @Mock
    private LatticeSecurityConfig config;
    @Mock
    private LatticeSecurityConfig.MerchantHierarchy merchantHierarchyConfig;
    @Mock
    private Instance<RedisDataSource> redisInstance;
    @Mock
    private Instance<MerchantAccessResolver> resolverInstance;
    @Mock
    private RedisDataSource redisDataSource;
    @Mock
    private TransactionalRedisDataSource transactionalRedisDataSource;
    @Mock
    private TransactionalKeyCommands<String> transactionalKeyCommands;
    @Mock
    private TransactionalSetCommands<String, String> transactionalSetCommands;
    @Mock
    private SetCommands<String, String> setCommands;
    @Mock
    private KeyCommands<String> keyCommands;
    @Mock
    private MerchantAccessResolver resolver;

    private static final UUID INTEGRATOR_ID = UUID.randomUUID();
    private static final UUID MERCHANT_1 = UUID.randomUUID();
    private static final UUID MERCHANT_2 = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        when(config.merchantHierarchy()).thenReturn(merchantHierarchyConfig);
        when(merchantHierarchyConfig.redisKeyPrefix()).thenReturn("latticepay:hierarchy");
        when(merchantHierarchyConfig.ttl()).thenReturn(Duration.ofHours(1));
        lenient().when(resolverInstance.isResolvable()).thenReturn(true);
        lenient().when(resolverInstance.get()).thenReturn(resolver);
    }

    @Nested
    @DisplayName("getAccessibleMerchantIds")
    class GetAccessibleMerchantIds {

        @Test
        @DisplayName("calls SPI directly when cache disabled")
        void callsSpiDirectly_whenCacheDisabled() {
            when(merchantHierarchyConfig.enabled()).thenReturn(false);
            when(resolver.resolveMerchantIds(INTEGRATOR_ID)).thenReturn(Set.of(MERCHANT_1, MERCHANT_2));

            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_ID);

            assertEquals(Set.of(MERCHANT_1, MERCHANT_2), result);
            verify(resolver).resolveMerchantIds(INTEGRATOR_ID);
            verifyNoInteractions(redisInstance);
        }

        @Test
        @DisplayName("returns cached set on cache hit without calling SPI")
        void returnsCachedSet_onCacheHit() {
            when(merchantHierarchyConfig.enabled()).thenReturn(true);
            when(redisInstance.isResolvable()).thenReturn(true);
            when(redisInstance.get()).thenReturn(redisDataSource);
            when(redisDataSource.set(String.class)).thenReturn(setCommands);
            when(redisDataSource.key()).thenReturn(keyCommands);
            when(setCommands.smembers(anyString())).thenReturn(Set.of(MERCHANT_1.toString(), MERCHANT_2.toString()));

            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_ID);

            assertEquals(Set.of(MERCHANT_1, MERCHANT_2), result);
            verify(setCommands).smembers(anyString());
            verifyNoInteractions(resolver);
        }

        @Test
        @DisplayName("calls SPI and populates cache on cache miss")
        void callsSpiAndPopulatesCache_onCacheMiss() {
            when(merchantHierarchyConfig.enabled()).thenReturn(true);
            when(redisInstance.isResolvable()).thenReturn(true);
            when(redisInstance.get()).thenReturn(redisDataSource);
            when(redisDataSource.set(String.class)).thenReturn(setCommands);
            when(redisDataSource.key()).thenReturn(keyCommands);
            when(setCommands.smembers(anyString())).thenReturn(Set.of());
            when(resolver.resolveMerchantIds(INTEGRATOR_ID)).thenReturn(Set.of(MERCHANT_1, MERCHANT_2));

            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);
            Set<UUID> result = cache.getAccessibleMerchantIds(INTEGRATOR_ID);

            assertEquals(Set.of(MERCHANT_1, MERCHANT_2), result);
            verify(setCommands).sadd(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), any(String[].class));
            verify(keyCommands).expire(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), eq(Duration.ofHours(1)));
        }

        @Test
        @DisplayName("throws IllegalStateException when no SPI provided")
        void throwsIllegalStateException_whenNoSpiProvided() {
            when(merchantHierarchyConfig.enabled()).thenReturn(false);
            when(resolverInstance.isResolvable()).thenReturn(false);

            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            assertThrows(IllegalStateException.class, () -> cache.getAccessibleMerchantIds(INTEGRATOR_ID));
        }
    }

    @Nested
    @DisplayName("constructor")
    class Constructor {

        @Test
        @DisplayName("throws IllegalStateException when enabled and Redis not available")
        void throwsIllegalStateException_whenEnabledAndRedisNotAvailable() {
            when(merchantHierarchyConfig.enabled()).thenReturn(true);
            when(redisInstance.isResolvable()).thenReturn(false);

            assertThrows(IllegalStateException.class,
                    () -> new MerchantHierarchyCache(config, redisInstance, resolverInstance));
        }
    }

    @Nested
    @DisplayName("write operations")
    class WriteOperations {

        @BeforeEach
        void setUpWriteOps() {
            when(merchantHierarchyConfig.enabled()).thenReturn(true);
            when(redisInstance.isResolvable()).thenReturn(true);
            when(redisInstance.get()).thenReturn(redisDataSource);
            when(redisDataSource.set(String.class)).thenReturn(setCommands);
            when(redisDataSource.key()).thenReturn(keyCommands);
            when(redisDataSource.withTransaction(any())).thenAnswer(inv -> {
                @SuppressWarnings("unchecked")
                Consumer<TransactionalRedisDataSource> consumer = inv.getArgument(0);
                when(transactionalRedisDataSource.key()).thenReturn(transactionalKeyCommands);
                when(transactionalRedisDataSource.set(String.class)).thenReturn(transactionalSetCommands);
                consumer.accept(transactionalRedisDataSource);
                return null;
            });
        }

        @Test
        @DisplayName("addMerchant calls SADD when enabled")
        void addMerchant_callsSadd_whenEnabled() {
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.addMerchant(INTEGRATOR_ID, MERCHANT_1);

            verify(setCommands).sadd(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), eq(MERCHANT_1.toString()));
            verify(keyCommands).expire(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), eq(Duration.ofHours(1)));
        }

        @Test
        @DisplayName("removeMerchant calls SREM when enabled")
        void removeMerchant_callsSrem_whenEnabled() {
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.removeMerchant(INTEGRATOR_ID, MERCHANT_1);

            verify(setCommands).srem(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), eq(MERCHANT_1.toString()));
        }

        @Test
        @DisplayName("evict calls DEL when enabled")
        void evict_callsDel_whenEnabled() {
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.evict(INTEGRATOR_ID);

            verify(keyCommands).del(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"));
        }

        @Test
        @DisplayName("setMerchantIds runs DEL, SADD and EXPIRE in transaction when non-empty")
        void setMerchantIds_callsDelSaddExpireInTransaction_whenEnabled() {
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.setMerchantIds(INTEGRATOR_ID, Set.of(MERCHANT_1, MERCHANT_2));

            verify(redisDataSource).withTransaction(any());
            verify(transactionalKeyCommands).del(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"));
            verify(transactionalSetCommands).sadd(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), any(String[].class));
            verify(transactionalKeyCommands).expire(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"), eq(Duration.ofHours(1)));
        }

        @Test
        @DisplayName("setMerchantIds runs only DEL in transaction when empty")
        void setMerchantIds_callsDelOnlyInTransaction_whenEmpty() {
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.setMerchantIds(INTEGRATOR_ID, Set.of());

            verify(redisDataSource).withTransaction(any());
            verify(transactionalKeyCommands).del(eq("latticepay:hierarchy:" + INTEGRATOR_ID + ":merchants"));
            verify(transactionalSetCommands, never()).sadd(anyString(), any(String[].class));
            verify(transactionalKeyCommands, never()).expire(anyString(), any(Duration.class));
        }

        @Test
        @DisplayName("addMerchant does nothing when disabled")
        void addMerchant_doesNothing_whenDisabled() {
            when(merchantHierarchyConfig.enabled()).thenReturn(false);
            var cache = new MerchantHierarchyCache(config, redisInstance, resolverInstance);

            cache.addMerchant(INTEGRATOR_ID, MERCHANT_1);

            verifyNoInteractions(redisInstance);
        }
    }
}
