package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestOperations;

@Component
@ConditionalOnGovsso
public class GovssoAuthorizationCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final DefaultAuthorizationCodeTokenResponseClient delegate;

    public GovssoAuthorizationCodeTokenResponseClient(
            @Qualifier("govssoRestTemplate") RestOperations restOperations) {
        this.delegate = new DefaultAuthorizationCodeTokenResponseClient();
        this.delegate.setRestOperations(restOperations);
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        return delegate.getTokenResponse(authorizationGrantRequest);
    }

}
