package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.LogoutSuccessRedirectProperties;
import ee.eesti.authentication.domain.GovssoSession;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNullElse;

@Service
@RequiredArgsConstructor
public class GovssoLogoutService {

    @NonNull
    private final ClientRegistrationRepository clientRegistrationRepository;

    @NonNull
    private LogoutSuccessRedirectProperties logoutSuccessRedirectProperties;

    @Value("${auth.provider}")
    private String registrationId;

    @Value("${security.oauth2.client.default-post-logout-redirect-uri-template}")
    private String defaultPostLogoutRedirectUriTemplate;

    public String logoutWithGovssoSession(GovssoSession govssoSession, String language, String postLogoutRedirectUri) {
        language = requireNonNullElse(language, "et");

        if (!isPostLogoutRedirectUriAllowed(postLogoutRedirectUri)) {
            postLogoutRedirectUri = getDefaultPostLogoutRedirectUri(language);
        }

        URI endSessionEndpoint = getEndSessionEndpoint();
        String govssoIdToken = govssoSession.idToken().getTokenValue();
        String logoutRequestUri = getLogoutRequestUri(endSessionEndpoint);

        return """
                <html>
                    <body onload='document.forms["logoutRedirectForm"].submit()'>
                        <form name="logoutRedirectForm" method="POST" action="%s" enctype="application/x-www-form-urlencoded">
                            <input type="hidden" name="id_token_hint" value="%s" />
                            <input type="hidden" name="post_logout_redirect_uri" value="%s" />
                            <input type="hidden" name="ui_locales" value="%s" />
                        </form>
                    </body>
                </html>
                """.formatted(logoutRequestUri, govssoIdToken, postLogoutRedirectUri, language);
    }

    public String logoutWithoutGovssoSession(String language, String postLogoutRedirectUri) {
        language = requireNonNullElse(language, "et");

        if (!isPostLogoutRedirectUriAllowed(postLogoutRedirectUri)) {
            postLogoutRedirectUri = getDefaultPostLogoutRedirectUri(language);
        }

        return postLogoutRedirectUri;
    }

    private boolean isPostLogoutRedirectUriAllowed(String postLogoutRedirectUri) {
        Set<String> whitelist = logoutSuccessRedirectProperties.getWhitelist();
        return StringUtils.isNotBlank(postLogoutRedirectUri)
                && whitelist != null
                && whitelist.contains(postLogoutRedirectUri);
    }

    private String getDefaultPostLogoutRedirectUri(@NonNull String language) {
        return UriComponentsBuilder.fromUriString(defaultPostLogoutRedirectUriTemplate)
                .buildAndExpand(Map.of("lang", language))
                .toUriString();
    }

    // Based on OidcClientInitiatedLogoutSuccessHandler
    private URI getEndSessionEndpoint() {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
        ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
        Object endSessionEndpoint = providerDetails.getConfigurationMetadata().get("end_session_endpoint");
        return URI.create(endSessionEndpoint.toString());
    }

    // Based on OidcClientInitiatedLogoutSuccessHandler
    private String getLogoutRequestUri(@NonNull URI endSessionEndpoint) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endSessionEndpoint);
        return builder.encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }
}
