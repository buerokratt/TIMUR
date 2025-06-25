package ee.eesti.authentication.constant;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Set;

@ConfigurationProperties("auth.success.redirect")
@Data
@Component
public class AuthSuccessRedirectProperties {

    private Set<String> whitelist;

}
