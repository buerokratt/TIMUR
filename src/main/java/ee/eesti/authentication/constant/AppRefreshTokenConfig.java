package ee.eesti.authentication.constant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties("refresh-token")
@Data
@Component
public class AppRefreshTokenConfig {

    private long ttlInDays;
    private String cookieName;
    private int tokenLength;
    private String clientId;
    private String encryptionKey;
}
