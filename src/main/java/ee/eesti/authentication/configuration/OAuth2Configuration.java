package ee.eesti.authentication.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Map;

import static org.apache.commons.lang3.StringUtils.defaultString;

/**
 * OAuth security configuration
 * <p>
 *
 * Note! Spring does seem to provide some default variables for oauth2 configuration.
 * <p>
 * Due to the lack of documentation, these standard variables might not work with different configurations.
 *
 */
@Configuration
public class OAuth2Configuration {

    @Value("${security.oauth2.client.user-authorization-uri}")
    private String authorizationUri;
    @Value("${auth.provider}")
    private String registrationId;
    @Value("${security.oauth2.client.client-id}")
    private String clientId;
    @Value("${security.oauth2.client.client-id}")
    private String clientName;
    @Value("${security.oauth2.client.client-secret}")
    private String clientSecret;
    @Value("${security.oauth2.client.registered-redirect-uri}")
    private String redirectUrlTemplate;
    @Value("${security.oauth2.client.access-token-uri}")
    private String tokenUri;
    @Value("${security.oauth2.client.logout-uri}")
    private String logoutUri;
    @Value("${security.oauth2.resource.jwk.key-set-uri}")
    private String jwkSetUri;
    @Value("${security.oauth2.provider.issuer-uri}")
    private String issuerUri;
    @Value("${security.oauth2.client.scope}")
    private String scope;
    @Value("${security.oauth2.client.audience}")
    private String audience;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public ClientRegistration clientRegistration() {
        return ClientRegistration
                .withRegistrationId(registrationId)
                .authorizationUri(authorizationUri)
                .clientId(clientId)
                .clientName(clientName)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUrlTemplate)
                .tokenUri(tokenUri)
                .jwkSetUri(jwkSetUri)
                .issuerUri(issuerUri)
                // Same way as Spring Security puts this when using https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig (spring.security.oauth2.client.provider.govsso.issuer-uri=https://govsso-demo.ria.ee/).
                .providerConfigurationMetadata(Map.of(
                        "end_session_endpoint", logoutUri,
                        "audience", audience.split("[\\s]+")))
                .scope(defaultString(scope).split("[\\s]+"))
                .build();
    }

}
