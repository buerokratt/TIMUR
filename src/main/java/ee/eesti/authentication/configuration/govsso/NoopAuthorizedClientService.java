package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;

@ConditionalOnGovsso
@Component
@Slf4j
public class NoopAuthorizedClientService implements OAuth2AuthorizedClientService {

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        throw new NotImplementedException();
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        log.debug("Not saving authorized client - using no-op implementation.");
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        log.debug("Not removing authorized client - using no-op implementation.");
    }
}
