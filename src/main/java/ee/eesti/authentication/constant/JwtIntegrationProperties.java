package ee.eesti.authentication.constant;

import ee.eesti.authentication.domain.DeletableCookie;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import java.util.List;

@ConfigurationProperties("jwt-integration")
@Data
@Component
@Validated
public class JwtIntegrationProperties {

    private List<@Valid DeletableCookie> cookiesToDelete;

}
