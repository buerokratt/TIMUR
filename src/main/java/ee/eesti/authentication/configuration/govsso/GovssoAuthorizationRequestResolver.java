package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import ee.eesti.authentication.constant.EidasLevelOfAssurance;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

@Slf4j
@Component
@ConditionalOnGovsso
public class GovssoAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver requestResolver;

    public GovssoAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        this.requestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
        );
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest) {
        OAuth2AuthorizationRequest authorizationRequest = requestResolver.resolve(httpServletRequest);
        if (authorizationRequest == null) {
            return null;
        }
        return customizedAuthorizationRequest(authorizationRequest, httpServletRequest);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest httpServletRequest, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest =
                requestResolver.resolve(httpServletRequest, clientRegistrationId);
        if (authorizationRequest == null) {
            return null;
        }
        return customizedAuthorizationRequest(authorizationRequest, httpServletRequest);
    }

    private OAuth2AuthorizationRequest customizedAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest httpServletRequest) {
        Map<String, Object> additionalParameters = new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());

        String locale = httpServletRequest.getParameter("locale");

        HttpSession session = httpServletRequest.getSession();
        // TODO (AUT-997): review
        if (locale != null) {
            additionalParameters.put("ui_locales", locale);
            /*
                Using LOCALE_SESSION_ATTRIBUTE_NAME to store selected locale is compatible with
                Spring SessionLocaleResolver/LocaleChangeInterceptor. You cannot use LocaleChangeInterceptor alone
                to store selected authentication locale, because OAuth2AuthorizationRequestRedirectFilter performs
                redirect before LocaleChangeInterceptor has an opportunity to detect locale change.
             */
            session.setAttribute(LOCALE_SESSION_ATTRIBUTE_NAME, new Locale(locale));
        }

        String requestedAcrStr = httpServletRequest.getParameter("acr_values");
        EidasLevelOfAssurance acr = EidasLevelOfAssurance.SUBSTANTIAL;
        if (requestedAcrStr != null) {
            try {
                EidasLevelOfAssurance requestedAcr = EidasLevelOfAssurance.fromValue(requestedAcrStr);
                if (requestedAcr.isAtLeast(EidasLevelOfAssurance.SUBSTANTIAL)) { // only allow substantial or high acr
                    acr = requestedAcr;
                } else {
                    log.warn("Requested authorization with acr lower than allowed: '{}'. Using '{}' instead", requestedAcrStr, acr.getValue());
                }
            } catch (IllegalArgumentException e) {
                log.warn("Requested authorization with unknown acr value: '{}'. Using '{}' instead", requestedAcrStr, acr.getValue());
            }
        }
        additionalParameters.put("acr_values", acr.getValue());

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }

}
