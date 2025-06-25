package ee.eesti.authentication.service;

import ee.eesti.authentication.configuration.govsso.GovssoRefreshTokenTokenResponseClient;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.domain.GovssoSession;
import ee.eesti.authentication.domain.UserSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.stereotype.Service;

import java.util.Map;

import static java.util.Objects.requireNonNull;

@Slf4j
@Service
@RequiredArgsConstructor
public class GovssoUpdateSessionService {

    private final ClientRegistration clientRegistration;
    private final JwtUtils jwtUtils;
    private final JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory;
    private final GovssoAccessTokenService govssoAccessTokenService;
    private final GovssoSessionService govssoSessionService;
    private final GovssoRefreshTokenTokenResponseClient refreshTokenResponseClient;

    public ResponseEntity<Void> updateGovssoSession(HttpServletRequest request, HttpServletResponse response) {
        UserSession userSession = jwtUtils.getUserSession(request);
        return refreshTokensAndUpdateSession(userSession, response);
    }

    public ResponseEntity<Void> updateGovssoSession(String serializedJwt, HttpServletResponse response) {
        UserSession userSession = jwtUtils.getUserSession(serializedJwt);
        return refreshTokensAndUpdateSession(userSession, response);
    }

    public ResponseEntity<Void> refreshTokensAndUpdateSession(UserSession userSession, HttpServletResponse response) {
        if (userSession == null || userSession.govssoSession() == null) {
            log.info("Not updating GovSSO session, session not available");
            return ResponseEntity.badRequest().build();
        }

        String representablePartyCode = null;
        if (!userSession.userInfo().getRepresentedParty().getCode().equals(userSession.userInfo().getPersonalCode())) {
            representablePartyCode = userSession.userInfo().getRepresentedParty().getCode();
        }

        OAuth2AccessTokenResponse tokenResponse;
        try {
            tokenResponse = performRefreshTokenGrantRequest(
                    clientRegistration,
                    userSession.govssoSession().refreshToken(),
                    representablePartyCode);
        } catch (OAuth2AuthorizationException e) {
            log.error("GovSSO token request with refresh token failed", e);
            return ResponseEntity.internalServerError().build();
        }
        updateSavedGovssoSession(clientRegistration, tokenResponse, representablePartyCode);

        log.info("Session saved");

        return ResponseEntity.ok().build();
    }

    private void updateSavedGovssoSession(
            ClientRegistration clientRegistration,
            OAuth2AccessTokenResponse tokenResponse,
            String representablePartyCode
    ) {
        String idToken = (String) tokenResponse.getAdditionalParameters().get("id_token");
        Jwt validatedIdToken = idTokenDecoderFactory.createDecoder(clientRegistration).decode(idToken);
        OidcIdToken oidcIdToken = new OidcIdToken(
                validatedIdToken.getTokenValue(),
                validatedIdToken.getIssuedAt(),
                validatedIdToken.getExpiresAt(),
                validatedIdToken.getClaims());

        String accessToken = tokenResponse.getAccessToken().getTokenValue();
        Jwt validatedAccessToken = govssoAccessTokenService.decodeToken(accessToken);
        // TODO: RIG-5403: Doesn't feel like a great place for token validation. However GovssoAccessTokenService does
        //  not (currently) have access to representablePartyCode which is needed for the validation.
        if (representablePartyCode != null) {
            Map<String, Object> representee = validatedAccessToken.getClaimAsMap("representee");
            String sub = representee != null && representee.get("sub") != null
                    ? representee.get("sub").toString()
                    : null;
            if (representablePartyCode.equals(sub)) {
                log.error("updateSavedGovssoSession, Access Token representee.sub does not match representablePartyCode");
            }
        }
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                validatedAccessToken.getTokenValue(),
                validatedAccessToken.getIssuedAt(),
                validatedAccessToken.getExpiresAt());

        GovssoSession govssoSession = new GovssoSession(
                oidcIdToken,
                requireNonNull(tokenResponse.getRefreshToken()),
                oAuth2AccessToken);

        this.govssoSessionService.save(govssoSession);
    }

    private OAuth2AccessTokenResponse performRefreshTokenGrantRequest(
            ClientRegistration clientRegistration,
            OAuth2RefreshToken refreshToken,
            String representablePartyCode
    ) throws OAuth2AuthorizationException {
        GovssoRefreshTokenTokenResponseClient.Request tokenRequest = new GovssoRefreshTokenTokenResponseClient.Request(
                clientRegistration,
                refreshToken,
                representablePartyCode);
        return refreshTokenResponseClient.getTokenResponse(tokenRequest);
    }
}
