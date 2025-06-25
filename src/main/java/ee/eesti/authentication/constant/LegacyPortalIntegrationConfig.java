package ee.eesti.authentication.constant;


import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * properties relating to legacy portal integration. string from @ConfigurationProperties is used as prefix in properties files.
 * Field names as properties names in properties files.
 */
@Component
@ConfigurationProperties("legacy-portal-integration")
@Data
public class LegacyPortalIntegrationConfig {

    private int sessionTimeoutMinutes;
    private String requestIpHeader;
    private String requestIpAttribute;

}
