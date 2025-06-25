package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnGovsso
@RequiredArgsConstructor
public class GovssoOAuth2LoginConfigurer implements Customizer<OAuth2LoginConfigurer<HttpSecurity>> {

    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
    private final OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver;

    @Override
    public void customize(OAuth2LoginConfigurer<HttpSecurity> configurer) {
        // @formatter:off
        configurer
                .loginPage(frontPageRedirectUrl)
                .withObjectPostProcessor(new SetAuthenticationResultConverter())
                .redirectionEndpoint(redirectionEndpoint -> redirectionEndpoint.baseUri("/authenticate"))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient))
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .authorizationRequestResolver(oAuth2AuthorizationRequestResolver))
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler);
        // @formatter:on
    }

    private static class SetAuthenticationResultConverter
            implements ObjectPostProcessor<OAuth2LoginAuthenticationFilter> {

        @Override
        public <O extends OAuth2LoginAuthenticationFilter> O postProcess(O filter) {
            filter.setAuthenticationResultConverter(this::createGovssoAuthenticationToken);
            return filter;
        }

        private GovssoAuthenticationToken createGovssoAuthenticationToken(
                OAuth2LoginAuthenticationToken authenticationResult
        ) {
            return new GovssoAuthenticationToken(
                    authenticationResult.getPrincipal(),
                    authenticationResult.getAuthorities(),
                    authenticationResult.getClientRegistration().getRegistrationId(),
                    authenticationResult.getRefreshToken(),
                    authenticationResult.getAccessToken()
            );
        }

    }

}
