package ee.eesti.authentication.domain;

import lombok.NonNull;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

public record GovssoSession(
        @NonNull OidcIdToken idToken,
        @NonNull OAuth2RefreshToken refreshToken,
        @NonNull OAuth2AccessToken accessToken
) {

    public String sessionId() {
        return idToken.getClaimAsString("sid");
    }

}
