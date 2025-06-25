package ee.eesti.authentication.health;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "management.health.govsso")
public class GovssoHealthProperties {
    private boolean enabled;
    private String url;
    private int timeout;
}
