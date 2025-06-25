package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.JwtIntegrationProperties;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class CookieService {

    private final JwtIntegrationProperties jwtIntegrationProperties;

    public List<Cookie> getDeletableCookies(Cookie[] requestCookies) {
        Set<String> requestCookieNames = Stream.of(requestCookies)
                .map(Cookie::getName)
                .collect(Collectors.toSet());

        return jwtIntegrationProperties.getCookiesToDelete().stream()
                .filter(deletableCookie -> requestCookieNames.contains(deletableCookie.getName()))
                .map(deletableCookie -> {
                    Cookie responseCookie = new Cookie(deletableCookie.getName(), null);
                    responseCookie.setDomain(deletableCookie.getDomain());
                    responseCookie.setPath(deletableCookie.getPath());
                    responseCookie.setSecure(true);
                    responseCookie.setMaxAge(0);

                    return responseCookie;
                })
                .toList();
    }
}
