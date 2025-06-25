package ee.eesti.authentication.configuration.jwt;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import ee.eesti.authentication.constant.AppRefreshTokenConfig;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.GovssoSession;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.domain.UserSession;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.service.GovssoSessionService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * This class contains utility methods relating to jwt
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtUtils {

    private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;
    private final JwtSignatureConfig jwtSignatureConfig;
    private final JWSSigner rsassaSigner;
    private final JWSVerifier verifier;
    private final JWTClaimsSetVerifier<SecurityContext> claimsVerifier;
    private final JwtTokenInfoRepository jwtTokenInfoRepository;
    private final GovssoSessionService govssoSessionService;
    private final AppRefreshTokenConfig appRefreshTokenConfig;

    @Value("${jwt-integration.signature.secure-cookie:true}")
    private boolean secureCookie;

    @Value("${jwt-integration.signature.cookie-name}")
    private String timurJwtCookieName;

    /**
     * The claims "personalCode", "firstName" and "lastName" of the returned token
     * are filled from UserInfo.
     * Authorized party - the party to which the ID Token was issued. OIDC 1.0.
     * Used in Timur for defining mobile app token
     *
     * @param jwtTokenId id for token
     * @param userInfo information about user
     * @return filled with information from userInfo
     */
    public SignedJWT createSignedJwt(UUID jwtTokenId, UserInfo userInfo) {
        Date issueDate = userInfo.getLoggedInDate() == null
                ? new Date()
                : userInfo.getLoggedInDate();
        Date expirationDate = userInfo.getLoginExpireDate() == null
            ? DateUtils.addMinutes(issueDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
            : userInfo.getLoginExpireDate();

        Map<String, Object> claims = new HashMap<>();
        claims.put("personalCode", userInfo.getPersonalCode());
        claims.put("authenticatedAs", userInfo.getAuthenticatedAs());
        claims.put("hash", userInfo.getHash());
        claims.put("firstName", userInfo.getFirstName());
        claims.put("lastName", userInfo.getLastName());
        claims.put("authMethod", userInfo.getAuthMethod());
        claims.put("acr", userInfo.getAcr());
        claims.put("representedParty", Map.of(
                "id", userInfo.getRepresentedParty().getId(),
                "type", userInfo.getRepresentedParty().getType(),
                "code", userInfo.getRepresentedParty().getCode()
        ));
        claims.put("govssoSid", userInfo.getGovssoSessionId());
        claims.put("azp", userInfo.getAuthorizedParty());

        return getSignedJWTWithClaims(jwtTokenId, userInfo.getPersonalCode(), claims, issueDate, expirationDate);
    }

    /**
     *
     * @param jwtTokenId token id
     * @param subject  subject
     * @param claims map of claims
     * @param issueDate issue Date
     * @param expirationDate expiration Date
     * @return token filled with appropriate information from the input parameters
     */
    public SignedJWT getSignedJWTWithClaims(UUID jwtTokenId, String subject, Map<String, Object> claims, Date issueDate, Date expirationDate) {

        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(jwtTokenId.toString())
                .issuer(jwtSignatureConfig.getIssuer())
                .issueTime(issueDate)
                .notBeforeTime(issueDate)
                .expirationTime(expirationDate)
                .subject(subject);
        if (claims != null) {
            claims.forEach(claimsSetBuilder::claim);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.PS256),
                claimsSetBuilder.build());

        try {
            signedJWT.sign(rsassaSigner);
        } catch (JOSEException e) {
            log.error("cannot sign the JWT token", e);
            throw new IllegalStateException(e);
        }

        return signedJWT;
    }

    /**
     * Serializes the token into the cookie
     * @param signedJWT token to put into cookie
     * @return cookie containing token information
     */
    public ResponseCookie getJwtCookie(SignedJWT signedJWT) {
        return ResponseCookie
                .from(jwtSignatureConfig.getCookieName(), signedJWT.serialize())
                .secure(secureCookie)
                .httpOnly(true)
                .domain(jwtSignatureConfig.getCookieDomain())
                .path("/")
                .sameSite("Strict")
                .build();
    }

    /**
     * @return cookie that must be deleted when new JWT is generated
     */
    public Optional<ResponseCookie> getDeletableJwtCookieOnGeneration() {
        return Optional.ofNullable(jwtSignatureConfig.getCookieDeletionOnGeneration())
                .filter(cookieDeletionOnGeneration -> Boolean.TRUE.equals(cookieDeletionOnGeneration.getEnabled()))
                .map(cookieDeletionOnGeneration -> ResponseCookie
                        .from(jwtSignatureConfig.getCookieName(), null)
                        .maxAge(0)
                        .secure(secureCookie)
                        .httpOnly(true)
                        .domain(cookieDeletionOnGeneration.getDomain())
                        .path("/")
                        .sameSite("Strict")
                        .build());
    }

    public UserInfo parseJwt(@NonNull String jwtString) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        String personalCode = (String) signedJWT.getJWTClaimsSet().getClaim("personalCode");
        String authenticatedAs = (String) signedJWT.getJWTClaimsSet().getClaim("authenticatedAs");
        String hash = (String) signedJWT.getJWTClaimsSet().getClaim("hash");
        String firstName = (String) signedJWT.getJWTClaimsSet().getClaim("firstName");
        String lastName = (String) signedJWT.getJWTClaimsSet().getClaim("lastName");
        String authMethod = (String) signedJWT.getJWTClaimsSet().getClaim("authMethod");
        String acr = (String) signedJWT.getJWTClaimsSet().getClaim("acr");
        Map<String, Object> representedParty = signedJWT.getJWTClaimsSet().getJSONObjectClaim("representedParty");
        String govssoSessionId = (String) signedJWT.getJWTClaimsSet().getClaim("govssoSid");
        String authorizedParty = (String) signedJWT.getJWTClaimsSet().getClaim("azp");

        return new UserInfo(
                personalCode,
                authenticatedAs,
                hash,
                firstName,
                lastName,
                signedJWT.getJWTClaimsSet().getIssueTime(),
                signedJWT.getJWTClaimsSet().getExpirationTime(),
                authMethod,
                acr,
                RepresentableParty.builder()
                        .id((Long) representedParty.get("id"))
                        .type(RepresentableParty.Type.valueOf((String) representedParty.get("type")))
                        .code((String) representedParty.get("code"))
                        .build(),
                govssoSessionId,
                authorizedParty);
    }

    // TODO Rename methods to make clear that getUserInfo validates token, parseUserInfo doesn't.
    public UserInfo getUserInfo(String jwtTokenToCheck) {
        UserSession userSession = getUserSession(jwtTokenToCheck);
        return userSession != null ? userSession.userInfo() : null;
    }

    public UserSession getUserSession(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, timurJwtCookieName);
        if (cookie == null) {
            return null;
        }
        return this.getUserSession(cookie.getValue());
    }

    // TODO: `JwtUtils` does not feel like the right place for this method, but I'll leave it here for now.
    public UserSession getUserSession(String jwtTokenToCheck) {
        if (jwtTokenToCheck == null) {
            return null;
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtTokenToCheck);
            if( !signedJWT.verify(verifier)) {
                return null;
            }

            try {
                claimsVerifier.verify(signedJWT.getJWTClaimsSet(), null);
            } catch (BadJWTException e) {
                log.warn("token with id: {} is invalid: {}", signedJWT.getJWTClaimsSet().getJWTID(), e.getMessage());
                return null;
            }

            //check if the token is issued by us and not blacklisted already
            UUID uuid = UUID.fromString(signedJWT.getJWTClaimsSet().getJWTID());
            boolean isBlacklisted = jwtTokenInfoRepository.findByJwtUuid(uuid)
                    .map(jwtTokenInfo -> {
                        boolean blacklisted = jwtTokenInfo.isBlacklisted();
                        log.debug("token with id: {} is blacklisted: {}", uuid, blacklisted);
                        return blacklisted;
                    })
                    .orElseGet(() -> {
                        log.warn("token with id: {} is unknown", uuid);
                        return true;
                    });
            if (isBlacklisted) {
                return null;
            }

            UserInfo userInfo;
            try {
                userInfo = parseJwt(jwtTokenToCheck);
            } catch (ParseException e) {
                log.warn("could not parse UserInfo from JWT token string", e);
                return null;
            }

            String govssoSessionId = userInfo.getGovssoSessionId();
            GovssoSession govssoSession = null;
            if (govssoSessionId != null) {
                govssoSession = getGovssoSession(govssoSessionId);
                if (govssoSession == null && !isAppToken(userInfo)) {
                    return null;
                }
            }

            return new UserSession(userInfo, govssoSession);
        } catch (Exception e) {
            log.warn("token cannot be verified", e);
            return null;
        }
    }

    private boolean isAppToken(UserInfo userInfo){
        return appRefreshTokenConfig.getClientId().equals(userInfo.getAuthorizedParty());
    }

    public JWT decodeJwtAndVerifySignature(String jwtTokenToCheck) {
            if (jwtTokenToCheck == null) {
                return null;
            }
            SignedJWT signedJWT;
            try {
                signedJWT = SignedJWT.parse(jwtTokenToCheck);
                if (!signedJWT.verify(verifier)) {
                    return null;
                }
            } catch (ParseException | JOSEException e) {
                return null;
            }
            return signedJWT;
    }

    private GovssoSession getGovssoSession(String govssoSessionId) {
        Optional<GovssoSession> govssoSession = govssoSessionService.findById(govssoSessionId);
        if (govssoSession.isEmpty()) {
            log.info("GovSSO Session ID present in TIMUR token (\"{}\") but session not found, session expired?",
                    govssoSessionId);
            return null;
        }
        return govssoSession.get();
    }

    public static RSAKey getJwtSignKeyFromKeystore(String keyStoreType, InputStream keystoreInputStream, char[] keystorePassword, String keyAlias) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore jwtSignKeyStore = KeyStore.getInstance(keyStoreType);
        jwtSignKeyStore.load(keystoreInputStream, keystorePassword);

        JWKSet jwkSet = JWKSet.load(jwtSignKeyStore, name -> keystorePassword);
        return (RSAKey) jwkSet.getKeyByKeyId(keyAlias);
    }


}
