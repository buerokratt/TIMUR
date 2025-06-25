package ee.eesti.authentication.configuration.govsso;

import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.AppRefreshTokenConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.GovssoSession;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import ee.eesti.authentication.service.GovssoAccessTokenService;
import ee.eesti.authentication.service.GovssoSessionService;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.RefreshTokenService;
import ee.eesti.authentication.service.RightsService;
import ee.eesti.authentication.service.SessionsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OFFLINE_ACCESS;
import static ee.eesti.authentication.configuration.CustomSessionAttributeSecurityFilter.CALLBACK_URL;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;

@ConditionalOnGovsso
@Component
@Slf4j
public class GovssoAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    public static final String DEFAULT_LEGACY_SESSION_ID_VALUE = "-1";

    private final SessionsService sessionsService;
    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;
    private final AppRefreshTokenConfig appRefreshTokenConfig;
    private final JwtUtils jwtUtils;
    private final JwtTokenInfoService jwtTokenInfoService;
    private final GovssoSessionService govssoSessionService;
    private final GovssoAccessTokenService govssoAccessTokenService;
    private final RefreshTokenService refreshTokenService;


    public GovssoAuthenticationSuccessHandler(SessionsService sessionsService,
                                              LegacyPortalIntegrationConfig legacyPortalIntegrationConfig,
                                              JwtTokenInfoService jwtTokenInfoService,
                                              @Lazy JwtUtils jwtUtils,
                                              GovssoSessionService govssoSessionService,
                                              GovssoAccessTokenService govssoAccessTokenService,
                                              RefreshTokenService refreshTokenService,
                                              AppRefreshTokenConfig appRefreshTokenConfig
    ) {
        this.sessionsService = sessionsService;
        this.legacyPortalIntegrationConfig = legacyPortalIntegrationConfig;
        this.jwtTokenInfoService = jwtTokenInfoService;
        this.jwtUtils = jwtUtils;
        this.govssoSessionService = govssoSessionService;
        this.govssoAccessTokenService = govssoAccessTokenService;
        this.refreshTokenService = refreshTokenService;
        this.appRefreshTokenConfig = appRefreshTokenConfig;
    }

    /**
     * Response will do a redirect to legacy portal or to callback url depending on authentication details.
     * If details do not provide callback url or define a legacy session then jwtToken is written to the response.
     * Session attributes are set depending on authentication details.
     *
     * @param request        incoming request
     * @param response       current response
     * @param authentication successful authentication
     * @throws IOException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        GovssoAuthenticationToken authenticationToken = (GovssoAuthenticationToken) authentication;
        Map<String, Object> authenticationAttributes = authenticationToken.getPrincipal().getAttributes();
        HttpSession session = request.getSession();
        request.changeSessionId();
        UserInfo userInfo = createUserInfo(authenticationAttributes);

        authenticationToken.setDetails(userInfo);

        // Save the session entity to database and retrieve the corresponding cookie and add it to response
        ChannelType channelType = getChannelType(userInfo);

        String loginSessionIdValue = DEFAULT_LEGACY_SESSION_ID_VALUE;
        //creates legacy session for estonian personal codes only
        if (userInfo.isHasEstonianPersonalCode()) {
            String phoneNumber = (String) authenticationAttributes.get("phone_number");
            loginSessionIdValue = createLoginSession(request, phoneNumber, userInfo, channelType);
        }

        if (hasScopeOfflineAccess(session)) {
            userInfo.setAuthorizedParty(appRefreshTokenConfig.getClientId());
            String refreshToken = refreshTokenService.create(loginSessionIdValue);
            response.addHeader(SET_COOKIE, refreshTokenService.getResponseCookie(refreshToken));
        }

        SignedJWT signedJwt = performJwtAuth(response, userInfo, loginSessionIdValue);

        // TODO: RIG-5403: At this point authentication has succeeded. What to do if Access Token validation fails?
        String accessToken = authenticationToken.getAccessToken().getTokenValue();
        Jwt validatedAccessToken = govssoAccessTokenService.decodeToken(accessToken);
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                validatedAccessToken.getTokenValue(),
                validatedAccessToken.getIssuedAt(),
                validatedAccessToken.getExpiresAt());

        if (session.getAttribute(CALLBACK_URL) != null) {
            log.debug("redirecting back callback_url {}", session.getAttribute(CALLBACK_URL));
            response.sendRedirect((String) session.getAttribute(CALLBACK_URL));
        } else if (signedJwt != null) {
            log.debug("no redirect URL is found, returning JWT token instead");
            response.getWriter().write(signedJwt.serialize());
        } else {
            log.debug("no redirect URL is found and JWT not generated, returning nothing");
        }

        performSessionCleanup(session);

        OidcIdToken oidcIdToken = ((OidcUser) authenticationToken.getPrincipal()).getIdToken();
        GovssoSession govssoSession = new GovssoSession(
                oidcIdToken,
                authenticationToken.getRefreshToken(),
                oAuth2AccessToken);

        govssoSessionService.save(govssoSession);
    }

    private static boolean hasScopeOfflineAccess(HttpSession session) {
        return session.getAttribute(SCOPE) != null && Arrays.stream(session.getAttribute(SCOPE).toString().split(" ")).anyMatch(it -> it.equals(OFFLINE_ACCESS.getValue()));
    }

    private static ChannelType getChannelType(UserInfo userInfo) {
        ChannelType channelType = ChannelType.getByAmr(userInfo.getAuthMethod());
        if (channelType != null) {
            return channelType;
        }
        log.warn("unmapped channel type detected: {},  Please check the logs for more details", userInfo.getAuthMethod());
        return ChannelType.DEFAULT;
    }

    private SignedJWT performJwtAuth(HttpServletResponse response, UserInfo userInfo, String legacySessionIdValue) {
        UUID jwtTokenId = UUID.randomUUID();
        SignedJWT signedJwt = jwtUtils.createSignedJwt(jwtTokenId, userInfo);
        jwtTokenInfoService.createJwtTokenInfo(
                jwtTokenId,
                legacySessionIdValue,
                new Timestamp(userInfo.getLoginExpireDate().getTime()));

        // Delete JWT from another domain. TODO Remove when functionality has been in production for some time.
        jwtUtils.getDeletableJwtCookieOnGeneration().ifPresent(deletableJwtCookie ->
                response.addHeader(SET_COOKIE, deletableJwtCookie.toString()));

        //write JWT as cookie
        response.addHeader(SET_COOKIE, jwtUtils.getJwtCookie(signedJwt).toString());
        return signedJwt;
    }

    private String createLoginSession(HttpServletRequest request, String phoneNumber, UserInfo userInfo, ChannelType channelType) {
        SessionsEntity loginSession = sessionsService.openLegacyPortalLoginSession(
                request,
                userInfo,
                channelType,
                phoneNumber);
        return loginSession.getSessionId();
    }

    private void performSessionCleanup(HttpSession session) {
        session.removeAttribute(CALLBACK_URL);
        session.removeAttribute(legacyPortalIntegrationConfig.getRequestIpAttribute());
    }

    private UserInfo createUserInfo(Map<String, Object> attributes) {
        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode((String) attributes.get("sub"));
        userInfo.setAuthenticatedAs((String) attributes.get("sub"));
        userInfo.setHash(getUniqueRandomHash());
        userInfo.setFirstName((String) attributes.get("given_name"));
        userInfo.setLastName((String) attributes.get("family_name"));
        userInfo.setLoggedInDate(new Date());
        userInfo.setLoginExpireDate(
                DateUtils.addMinutes(
                        userInfo.getLoggedInDate(),
                        legacyPortalIntegrationConfig.getSessionTimeoutMinutes()));
        userInfo.setRepresentedParty(RepresentableParty.builder()
                .id(RightsService.CITIZEN_INSTITUTION_ID)
                .type(RepresentableParty.Type.CITIZEN)
                .code((String) attributes.get("sub"))
                .build());
        userInfo.setAuthMethod(extractAuthenticationMethodReference(attributes));
        userInfo.setAcr((String) attributes.get("acr"));
        userInfo.setGovssoSessionId((String) attributes.get("sid"));
        return userInfo;
    }

    private String getUniqueRandomHash() {
        return UUID.randomUUID().toString().concat(UUID.randomUUID().toString())
                .replace("-", "");
    }

    private String extractAuthenticationMethodReference(Map<String, Object> attributes) {
        List<?> amrArray = (List<?>) attributes.get("amr");
        return amrArray.get(0).toString();
    }

}
