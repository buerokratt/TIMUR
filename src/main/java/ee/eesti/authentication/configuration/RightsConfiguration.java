package ee.eesti.authentication.configuration;

import ee.eesti.authentication.constant.RightsProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@RequiredArgsConstructor
public class RightsConfiguration {
    private final RightsProperties rightsProperties;

    @Bean
    public WebClient rightsWebClient() {
        return WebClient.builder()
                .baseUrl(rightsProperties.getRightsUrl())
                .build();
    }

}
