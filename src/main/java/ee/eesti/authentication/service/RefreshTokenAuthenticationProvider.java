package ee.eesti.authentication.service;

import com.nimbusds.jwt.JWT;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.AppRefreshTokenEntity;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Objects;
import java.util.UUID;

import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.HttpHeaders.USER_AGENT;


@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenAuthenticationProvider {

    private final JwtTokenInfoService jwtTokenInfoService;

    private final RightsService rightsService;

    private final JwtUtils jwtUtils;

    private final RefreshTokenService refreshTokenService;

    private final SessionsRepository sessionsRepository;

    public void authenticate(String refreshToken, String idToken, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // ----- ID token -----

        JWT jwt;
        String oldJwtId;
        UserInfo userInfo;
        JwtTokenInfo jwtTokenInfo = null;

        try {
            jwt = getJwt(idToken);
            oldJwtId = getJwtId(jwt);
            jwtTokenInfo = getJwtTokenInfo(oldJwtId);
            userInfo = getUserInfo(jwt);

            if (jwtTokenInfo.isBlacklisted()) {
                log.error("Attempting to blacklist already blacklisted token");
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            if (!rightsService.hasRepresentableParty(userInfo, idToken)) {
                log.warn("User no longer allowed to represent party code: {}", userInfo.getRepresentedParty().getCode());
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }

        } catch (OAuth2AuthenticationException e) {
            if (jwtTokenInfo != null) {
                jwtTokenInfoService.findAllBySessionId(jwtTokenInfo.getLegacySessionId()).ifPresent(jwtTokens -> jwtTokens.forEach(jwtTokenInfoService::blacklist));
                refreshTokenService.invalidateByLegacySessionId(jwtTokenInfo.getLegacySessionId());
            }
            refreshTokenService.invalidateByToken(refreshToken);
            throw e;
        }

        jwtTokenInfoService.blacklist(jwtTokenInfo);

        // ----- Refresh token -----

        AppRefreshTokenEntity appRefreshTokenEntity = refreshTokenService.findByToken(refreshToken);
        if (appRefreshTokenEntity == null) {
            refreshTokenService.invalidateByLegacySessionId(jwtTokenInfo.getLegacySessionId());
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (log.isTraceEnabled()) {
            log.trace("Retrieved authorization with refresh token");
        }

        if (appRefreshTokenEntity.isExpired()) {
            log.error("Attempt to authenticate with expired RefreshToken");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (appRefreshTokenEntity.isInvalidated()) {
            log.error("Attempt to authenticate with invalidated RefreshToken");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        refreshTokenService.invalidateByLegacySessionId(appRefreshTokenEntity.getLegacySessionId());

        if (sessionsMatch(jwtTokenInfo.getLegacySessionId(), appRefreshTokenEntity.getLegacySessionId())) {
            log.error("Attempt to authenticate with JWT and RefreshToken with mismatching sessions");
            refreshTokenService.invalidateByLegacySessionId(jwtTokenInfo.getLegacySessionId());
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        SessionsEntity sessionsEntity = sessionsRepository.findBySessionId(appRefreshTokenEntity.getLegacySessionId()).orElseThrow();
        if (!Objects.equals(sessionsEntity.getBrowser(), request.getHeader(USER_AGENT))) {
            log.error("Session user agent not matching with token refresh request");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (log.isTraceEnabled()) {
            log.trace("Generated refresh token");
        }

        response.addHeader(SET_COOKIE, refreshTokenService.getResponseCookie(refreshTokenService.create(appRefreshTokenEntity.getLegacySessionId()))
        );

        jwtTokenInfoService.extendSessionObtainedFromJwt(oldJwtId, userInfo, request, response);
    }

    private JWT getJwt(String idToken) {
        JWT oldJwt = jwtUtils.decodeJwtAndVerifySignature(idToken);
        if (oldJwt == null) {
            log.error("Unable to verify JWT");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return oldJwt;
    }

    private static String getJwtId(JWT oldJwt) {
        String oldJwtId;
        try {
            oldJwtId = oldJwt.getJWTClaimsSet().getJWTID();
        } catch (ParseException e) {
            log.error("Cannot parse JWT uid. ");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        return oldJwtId;
    }

    private JwtTokenInfo getJwtTokenInfo(String oldJwtId) {
        return jwtTokenInfoService.findById(UUID.fromString(oldJwtId))
                .orElseThrow(() -> new OAuth2AuthenticationException("Old jwt token info is not found for blacklisting"));
    }

    private UserInfo getUserInfo(JWT oldJwt) {
        UserInfo userInfo;
        try {
            userInfo = jwtUtils.parseJwt(oldJwt.serialize());
        } catch (ParseException e) {
            log.warn("Could not parse UserInfo from JWT token string", e);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        return userInfo;
    }

    private static boolean sessionsMatch(String jwtSessionId, String refreshTokenSessionId) {
        return !Objects.equals(jwtSessionId, refreshTokenSessionId);
    }
}
