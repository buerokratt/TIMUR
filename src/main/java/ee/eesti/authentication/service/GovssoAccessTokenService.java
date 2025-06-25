package ee.eesti.authentication.service;

import ee.eesti.authentication.configuration.govsso.GovssoAccessTokenDecoderFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestOperations;

@Service
public class GovssoAccessTokenService {

    private final JwtDecoder jwtDecoder;

    public GovssoAccessTokenService(
            ClientRegistration clientRegistration,
            @Qualifier("govssoRestTemplate") RestOperations restOperations,
            @Value("${security.oauth2.client.audience}") String audience
    ) {
        GovssoAccessTokenDecoderFactory tokenDecoderFactory =
                new GovssoAccessTokenDecoderFactory(restOperations, audience);
        jwtDecoder = tokenDecoderFactory.createDecoder(clientRegistration);
    }

    public Jwt decodeToken(String token) {
        return jwtDecoder.decode(token);
    }
}
