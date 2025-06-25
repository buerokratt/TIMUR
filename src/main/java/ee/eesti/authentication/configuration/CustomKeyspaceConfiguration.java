package ee.eesti.authentication.configuration;

import ee.eesti.authentication.repository.entity.GovssoSessionEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.convert.KeyspaceConfiguration;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Slf4j
@Component
public class CustomKeyspaceConfiguration extends KeyspaceConfiguration {

    public CustomKeyspaceConfiguration(
            // Default timeToLive = 12h (max session lifetime with current GovSSO implementation) + 1h (buffer, so that redirecting
            // to logout would work for some time after token expiration).
            @Value("${redis.govsso.session-ttl:13h}")
            Duration govssoSessionTtl
    ) {
        super();
        this.addKeyspaceSettings(buildGovssoSessionSettings(govssoSessionTtl));
    }

    private KeyspaceSettings buildGovssoSessionSettings(Duration govssoSessionTtl) {
        log.debug("GovssoSession TTL: {}", govssoSessionTtl);

        KeyspaceSettings govssoSessionSettings = new KeyspaceSettings(GovssoSessionEntity.class, "GovssoSession");
        govssoSessionSettings.setTimeToLive(govssoSessionTtl.toSeconds());

        return govssoSessionSettings;
    }

}
