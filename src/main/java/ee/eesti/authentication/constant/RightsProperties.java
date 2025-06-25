package ee.eesti.authentication.constant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties("rig-gateway")
@Data
@Component
public class RightsProperties {

    private String rightsUrl;

}
