package ee.eesti.authentication.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import static org.springframework.web.servlet.i18n.SessionLocaleResolver.LOCALE_SESSION_ATTRIBUTE_NAME;

@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Value("${frontpage.redirect.url}")
    private String frontPageRedirectUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        HttpSession session = request.getSession();
        request.changeSessionId();

        if (!"user_cancel".equals(request.getParameter("error"))) {
            log.error("Authentication failure", exception);
            return;
        }

        Optional<Cookie> callbackUrlCookie = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("callback_url"))
                .findFirst();

        if (callbackUrlCookie.isPresent()) {
            String callbackUrlDecoded = URLDecoder.decode(callbackUrlCookie.get().getValue(), StandardCharsets.UTF_8);
            log.debug("user cancelled authentication, redirecting back to URL decoded request cookie callback_url {}", callbackUrlDecoded);
            response.sendRedirect(callbackUrlDecoded);
        } else if (frontPageRedirectUrl != null && session.getAttribute(LOCALE_SESSION_ATTRIBUTE_NAME) != null) {
            String redirectionUrl = frontPageRedirectUrl + session.getAttribute(LOCALE_SESSION_ATTRIBUTE_NAME) + "/";
            log.debug("user cancelled authentication, redirecting back to property frontPageRedirectUrl with session attribute locale {}", redirectionUrl);
            response.sendRedirect(redirectionUrl);
        } else if (frontPageRedirectUrl != null) {
            log.debug("user cancelled authentication, redirecting back to property frontPageRedirectUrl {}", frontPageRedirectUrl);
            response.sendRedirect(frontPageRedirectUrl);
        } else {
            log.error("user cancelled authentication, unable to redirect");
        }
    }

}
