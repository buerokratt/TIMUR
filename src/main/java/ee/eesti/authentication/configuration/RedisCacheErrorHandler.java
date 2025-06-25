package ee.eesti.authentication.configuration;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.interceptor.SimpleCacheErrorHandler;

@Slf4j
public class RedisCacheErrorHandler extends SimpleCacheErrorHandler {

    @Override
    public void handleCacheGetError(@NonNull RuntimeException exception, @NonNull Cache cache, @NonNull Object key) {
        log.error("Cache GET exception received for: cache : {} , key : {}", cache, key);
        log.error("Exception: ", exception);
    }

    @Override
    public void handleCachePutError(@NonNull RuntimeException exception, @NonNull Cache cache, @NonNull Object key, Object value) {
        log.error("Cache PUT exception: cache : {} , key : {}", cache, key);
        log.error("Exception: ", exception);
    }

    @Override
    public void handleCacheEvictError(@NonNull RuntimeException exception, @NonNull Cache cache, @NonNull Object key) {
        log.error("Cache EVICT exception: cache : {} , key : {}", cache, key);
        log.error("Exception: ", exception);
    }

    @Override
    public void handleCacheClearError(@NonNull RuntimeException exception, @NonNull Cache cache) {
        log.error("Cache CLEAR exception: cache : {}", cache);
        log.error("Exception: ", exception);
    }
}
