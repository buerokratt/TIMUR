package ee.eesti.authentication.constant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Set;

@ConfigurationProperties("logout.success.redirect")
@Data
@Component
public class LogoutSuccessRedirectProperties {

    private Set<String> whitelist;

}
