package ee.eesti.authentication.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.data.redis.LettuceClientConfigurationBuilderCustomizer;
import org.springframework.cache.annotation.CachingConfigurer;
import org.springframework.cache.interceptor.CacheErrorHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

@Slf4j
@Configuration
@EnableRedisRepositories(keyspaceConfiguration = CustomKeyspaceConfiguration.class)
public class RedisConfiguration implements CachingConfigurer {

    @Configuration
    @ConditionalOnExpression("${spring.data.redis.ssl.enabled:false} && !${redis.ssl.verify-peer:true}")
    public static class InsecureSslRedisConfiguration {

        @Bean
        public LettuceClientConfigurationBuilderCustomizer insecureSslRedisCustomizer() {
            return clientConfigurationBuilder -> {
                log.warn("Disabling peer verification - any certificate allowed");

                clientConfigurationBuilder
                        .useSsl()
                        .disablePeerVerification();
            };
        }

    }

    @Override
    public CacheErrorHandler errorHandler() {
        return new RedisCacheErrorHandler();
    }

}
