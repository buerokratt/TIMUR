package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.JwtIntegrationProperties;
import ee.eesti.authentication.domain.DeletableCookie;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.Cookie;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class CookieServiceTest {

    @Mock
    JwtIntegrationProperties jwtIntegrationProperties;

    @InjectMocks
    CookieService cookieService;

    @Test
    void getDeletableCookies() {
        doReturn(List.of(
                createDeletableCookie("JWTTOKEN", "arendus.eesti.ee", "/")
        )).when(jwtIntegrationProperties).getCookiesToDelete();

        Cookie[] requestCookies = new Cookie[]{
                new Cookie("JWTTOKEN", "VALUE"),
                new Cookie("JSESSIONID", "VALUE")
        };

        assertThat(cookieService.getDeletableCookies(requestCookies))
                .extracting("name", "domain", "path", "value", "maxAge", "secure")
                .containsExactlyInAnyOrder(
                        tuple("JWTTOKEN", "arendus.eesti.ee", "/", null, 0, true)
                );
    }

    private DeletableCookie createDeletableCookie(String name, String domain, String path) {
        DeletableCookie deletableCookie = new DeletableCookie();
        deletableCookie.setName(name);
        deletableCookie.setDomain(domain);
        deletableCookie.setPath(path);

        return deletableCookie;
    }

}
