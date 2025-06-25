package ee.eesti.authentication.service;

import ee.eesti.authentication.configuration.govsso.GovssoLogoutTokenDecoderFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestOperations;

@Service
public class GovssoLogoutTokenService {

    private final JwtDecoder jwtDecoder;

    public GovssoLogoutTokenService(
            ClientRegistration clientRegistration, @Qualifier("govssoRestTemplate") RestOperations restOperations) {
        GovssoLogoutTokenDecoderFactory tokenDecoderFactory = new GovssoLogoutTokenDecoderFactory(restOperations);
        jwtDecoder = tokenDecoderFactory.createDecoder(clientRegistration);
    }

    public String validateAndParseSessionId(String oidcLogoutToken) {
        Jwt jwt = jwtDecoder.decode(oidcLogoutToken);
        return jwt.getClaim("sid");
    }

}
