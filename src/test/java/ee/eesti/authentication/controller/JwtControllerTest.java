package ee.eesti.authentication.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.configuration.SecurityConfigurationTest;
import ee.eesti.authentication.configuration.govsso.GovssoRefreshTokenTokenResponseClient;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.connector.RightsClient;
import ee.eesti.authentication.constant.AppRefreshTokenConfig;
import ee.eesti.authentication.constant.EidasLevelOfAssurance;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.RightsRepresentablePartiesResponse;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.repository.GovssoSessionRepository;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.GovssoSessionEntity;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import ee.eesti.authentication.service.GovssoAccessTokenService;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.validation.constraints.NotNull;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static ee.eesti.authentication.handlers.RestExceptionHandler.ERROR_ID_HEADER_KEY;
import static java.sql.Timestamp.from;
import static java.time.temporal.ChronoUnit.HOURS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwtControllerTest extends AbstractSpringBasedTest {

    private static final String DEFAULT_SESSION_ID_1 = "q6pzhtnlb0vppk2s1kj8jbz6rw003tvb";
    private static final String DEFAULT_PERSONAL_CODE = "11223344551";
    private static final String GOVSSO_SESSION_ID = "govsso-session-id-1234";
    private static final String SUBJECT = "EE12345678901";
    private static final String USER_AUTHORIZATION_URI = "https://govsso.test/oidc/authorize";

    @Autowired
    private MockMvc mvc;

    @MockBean
    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeMockClient;

    @MockBean
    private GovssoRefreshTokenTokenResponseClient refreshTokenMockClient;

    @Mock
    private JwtDecoder jwtDecoder;

    @MockBean
    private GovssoAccessTokenService govssoAccessTokenService;

    @MockBean
    private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory;

    @Autowired
    private JwtSignatureConfig jwtSignatureConfig;

    @Autowired
    private LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    @Autowired
    private JWSSigner jwsSigner;

    @MockBean
    private GovssoSessionRepository govssoSessionRepository;

    @Autowired
    private JwtTokenInfoService jwtTokenInfoService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private AppRefreshTokenConfig appRefreshTokenConfig;

    @Autowired
    private JwtTokenInfoRepository jwtTokenInfoRepository;

    @Autowired
    private SessionsRepository sessionsRepository;

    @MockBean
    private RightsClient rightsClient;

    @Autowired
    private JwtUtils jwtUtils;

    @BeforeEach
    void init() throws Exception {
        jwtTokenInfoRepository.deleteAll();
        sessionsRepository.deleteAll();

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OidcParameterNames.ID_TOKEN, "ID");
        Map<String, Object> representee = new HashMap<>();
        representee.put("sub", "personalCode");
        additionalParams.put("representee", representee);
        OAuth2AccessTokenResponse value = OAuth2AccessTokenResponse
                .withToken("test")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .additionalParameters(additionalParams)
                .refreshToken("refresh-token")
                .build();

        AtomicReference<Object> nonce = new AtomicReference<>();

        when(authorizationCodeMockClient.getTokenResponse(any())).thenAnswer(invocation -> {
            nonce.set(invocation.getArgument(0, OAuth2AuthorizationCodeGrantRequest.class)
                    .getAuthorizationExchange()
                    .getAuthorizationRequest()
                    .getAdditionalParameters()
                    .get(OidcParameterNames.NONCE));
            return value;
        });

        when(refreshTokenMockClient.getTokenResponse(any())).thenReturn(value);

        HashMap<String, Object> headers = new HashMap<>();
        headers.put("random", "stuff");
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("more", "random stuff");
        claims.put(IdTokenClaimNames.ISS, new URL(USER_AUTHORIZATION_URI));
        claims.put(IdTokenClaimNames.SUB, SUBJECT);
        claims.put(IdTokenClaimNames.AUD, Collections.singletonList("eesti-frontend"));
        claims.put("sid", GOVSSO_SESSION_ID);
        claims.put(IdTokenClaimNames.ACR, EidasLevelOfAssurance.SUBSTANTIAL);
        claims.put(IdTokenClaimNames.AMR, Collections.singletonList("idcard"));
        claims.put("given_name", "MARY ÄNN");
        claims.put("family_name", "O’CONNEŽ-ŠUSLIK");
        when(jwtDecoder.decode(anyString())).thenAnswer(invocation -> {
            claims.put(IdTokenClaimNames.NONCE, nonce.get());
            return new Jwt("test", Instant.now(), Instant.MAX, headers, claims);
        });
        when(govssoAccessTokenService.decodeToken(anyString())).thenAnswer(invocation -> {
            claims.put(IdTokenClaimNames.NONCE, nonce.get());
            return new Jwt("test", Instant.now(), Instant.MAX, headers, claims);
        });
        when(jwtDecoderFactory.createDecoder(any())).thenReturn(jwtDecoder);
    }

    @Test
    void loadPublicKey() throws Exception {

        RSAKey rsaKey = SecurityConfigurationTest.getRSAKey(jwtSignatureConfig);
        PublicKey publicKey = rsaKey.toPublicKey();

        mvc.perform(get("/jwt/verification-key"))
                .andExpect(status().isOk())
                .andExpect(result -> {
                    String keyString = result.getResponse()
                            .getContentAsString();

                    keyString = keyString.replace("-----BEGIN PUBLIC KEY-----\n", "");
                    keyString = keyString.replace("-----END PUBLIC KEY-----", "");

                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(keyString));
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey obtainedThroughWeb = keyFactory.generatePublic(pubKeySpec);
                    assertThat(obtainedThroughWeb, is(publicKey));

                })
        ;
    }

    @Test
    void decodeJwtFromCookie_ValidToken_ReturnsUserInfo() throws Exception {

        String personalCode = "12345678901";
        String firstName = "John";
        String lastName = "Doe";
        String authMethod = "eIDAS";
        String acr = "high";

        Map<String, String> claimSetToAdd = new HashMap<>();
        claimSetToAdd.put("personalCode", personalCode);
        claimSetToAdd.put("firstName", firstName);
        claimSetToAdd.put("lastName", lastName);
        claimSetToAdd.put("authMethod", authMethod);
        claimSetToAdd.put("acr", acr);
        claimSetToAdd.put("govssoSid", GOVSSO_SESSION_ID);

        mockGovssoSession();

        //Valid token info
        UUID jwtId = UUID.randomUUID();
        Date issueTime = DateUtils.truncate(new Date(), Calendar.SECOND);
        Date expirationDate = DateUtils.addMinutes(issueTime, 30);

        jwtTokenInfoService.createJwtTokenInfo(jwtId, DEFAULT_SESSION_ID_1, new Timestamp(expirationDate.getTime()));

        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), getJwtTokenString(issueTime, expirationDate, jwtSignatureConfig.getIssuer(), jwtId.toString(), claimSetToAdd, personalCode))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("personalCode", is(personalCode)))
                .andExpect(jsonPath("firstName", is(firstName)))
                .andExpect(jsonPath("lastName", is(lastName)))
                .andExpect(jsonPath("loggedInDate", is(issueTime.getTime())))
                .andExpect(jsonPath("loginExpireDate", is(expirationDate.getTime())))
                .andExpect(jsonPath("authMethod", is(authMethod)))
                .andExpect(jsonPath("acr", is(acr)))
                .andExpect(jsonPath("representedParty.id", is(0)))
                .andExpect(jsonPath("representedParty.type", is(RepresentableParty.Type.CITIZEN.name())))
                .andExpect(jsonPath("representedParty.code", is(personalCode)))
                .andExpect(jsonPath("govsso.sessionId", is(GOVSSO_SESSION_ID)))
                .andExpect(jsonPath("govsso.token", is("access-token")))
                .andExpect(jsonPath("govsso.expiration", notNullValue()))
        ;
    }

    @Test
    void decodeJwtFromCookie_NoCookie_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        get("/jwt/userinfo"))
                .andExpect(status().isBadRequest())
        ;
    }

    @Test
    void decodeJwtFromCookie_NotParseableCookie_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), "some random string")))
                .andExpect(status().isBadRequest())
        ;
    }

    @Test
    void decodeJwtFromCookie_MissingJwtCookie_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(new Cookie("NOT_JWT", null)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyToken_ValidToken_ReturnsOk() throws Exception {
        UUID jwtId = UUID.randomUUID();
        Date expirationTime = DateUtils.addMinutes(new Date(), 30);

        jwtTokenInfoService.createJwtTokenInfo(jwtId, DEFAULT_SESSION_ID_1, new Timestamp(expirationTime.getTime()));

        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), expirationTime, jwtSignatureConfig.getIssuer(), jwtId.toString(), null, DEFAULT_PERSONAL_CODE)))
                .andExpect(status().isOk());
    }

    @Test
    void verifyToken_InvalidToken_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        post("/jwt/verify")
                                .content("garbage here"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyToken_ExpiredToken_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), new Date(), jwtSignatureConfig.getIssuer(), UUID.randomUUID()
                                        .toString(), null, DEFAULT_PERSONAL_CODE)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verifyToken_InvalidIssuer_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        post("/jwt/verify")
                                .content(getJwtTokenString(new Date(), new Date(), "not a real issuer thing", UUID.randomUUID()
                                        .toString(), null, DEFAULT_PERSONAL_CODE)))
                .andExpect(status().isBadRequest());

    }

    private String getJwtTokenString(Date issueTime, Date expirationDate, String issuer, String jwtId, Map<String, String> claimSetToAdd, String personalCode) throws JOSEException {
        JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder()
                .subject(personalCode)
                .notBeforeTime(issueTime)
                .expirationTime(expirationDate)
                .jwtID(jwtId)
                .issueTime(issueTime)
                .issuer(issuer);

        claimSetBuilder.claim("representedParty", Map.of(
                "id", 0L,
                "type", RepresentableParty.Type.CITIZEN,
                "code", personalCode
        ));

        if (claimSetToAdd != null) {
            claimSetToAdd.forEach(claimSetBuilder::claim);
        }

        JWTClaimsSet claimsSet = claimSetBuilder.build();


        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.PS256), claimsSet);
        signedJWT.sign(jwsSigner);

        return signedJWT.serialize();
    }

    @Test
    @Transactional
    void endSession_JwtCookieWithoutExistingGovssoIdToken_EndsSessionAndRedirectsToPortal() throws Exception {
        JwtTokenInfo jwtTokenInfo = createTokenAndSession("q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3");
        UUID jwtToken = jwtTokenInfo.getJwtUuid();
        String jwtToInvalidate = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), null, "11223344556");

        mvc.perform(
                        get("/jwt/end-session")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtToInvalidate))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "http://localhost/et/tagasiside"))
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(nullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), 0))
                .andExpect(cookie().doesNotExist("NOT_REMOVABLE"));

        // Invalidated legacy session should have the validTo in the past
        SessionsEntity expiredLegacySession = sessionsRepository
                .findBySessionId(jwtTokenInfo.getLegacySessionId())
                .orElseThrow(IllegalArgumentException::new);

        assertTrue(expiredLegacySession.getValidTo()
                .isBefore(LocalDateTime.now()));

        mvc.perform(post("/jwt/verify")
                        .content(jwtToInvalidate))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Transactional
    void getSessions_JwtCookie_ListOfSessions() throws Exception {
        JwtTokenInfo jwtTokenInfo = createTokenAndSession("q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3");
        createTokenAndSession("w6pzhtnlb0vppk2s1kj8jbz6rw003tvc3");
        UUID jwtToken = jwtTokenInfo.getJwtUuid();
        String jwtCookie = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), null, "11223344556");

        mvc.perform(
                        get("/jwt/active-sessions")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtCookie))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE")))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[0].id").exists())
                .andExpect(jsonPath("$[0].channel").value(nullValue()))
                .andExpect(jsonPath("$[0].sessionId").value("q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3"))
                .andExpect(jsonPath("$[0].personalCode").value("EE11223344556"))
                .andExpect(jsonPath("$[0].authenticatedAs").value(nullValue()))
                .andExpect(jsonPath("$[0].hash").value(nullValue()))
                .andExpect(jsonPath("$[0].givenname").value(nullValue()))
                .andExpect(jsonPath("$[0].surname").value(nullValue()))
                .andExpect(jsonPath("$[0].params").value("{{LANG,ee},{XMLHTTP,YES}}"))
                .andExpect(jsonPath("$[0].created").value(nullValue()))
                .andExpect(jsonPath("$[0].ip").value(nullValue()))
                .andExpect(jsonPath("$[0].browser").value(nullValue()))
                .andExpect(jsonPath("$[0].username").value(nullValue()))
                .andExpect(jsonPath("$[0].loginLevel").value(nullValue()))
                .andExpect(jsonPath("$[0].mobileNumber").value(nullValue()))
                .andExpect(jsonPath("$[0].certificateType").value(nullValue()))
                .andExpect(jsonPath("$[0].current").value(true))

                .andExpect(jsonPath("$[1].id").exists())
                .andExpect(jsonPath("$[1].channel").value(nullValue()))
                .andExpect(jsonPath("$[1].sessionId").value("w6pzhtnlb0vppk2s1kj8jbz6rw003tvc3"))
                .andExpect(jsonPath("$[1].personalCode").value("EE11223344556"))
                .andExpect(jsonPath("$[1].authenticatedAs").value(nullValue()))
                .andExpect(jsonPath("$[1].hash").value(nullValue()))
                .andExpect(jsonPath("$[1].givenname").value(nullValue()))
                .andExpect(jsonPath("$[1].surname").value(nullValue()))
                .andExpect(jsonPath("$[1].params").value("{{LANG,ee},{XMLHTTP,YES}}"))
                .andExpect(jsonPath("$[1].created").value(nullValue()))
                .andExpect(jsonPath("$[1].ip").value(nullValue()))
                .andExpect(jsonPath("$[1].browser").value(nullValue()))
                .andExpect(jsonPath("$[1].username").value(nullValue()))
                .andExpect(jsonPath("$[1].loginLevel").value(nullValue()))
                .andExpect(jsonPath("$[1].mobileNumber").value(nullValue()))
                .andExpect(jsonPath("$[1].certificateType").value(nullValue()))
                .andExpect(jsonPath("$[1].current").value(false));
    }

    @Test
    @Transactional
    void getSessions_InvalidJwtCookie_BadRequest() throws Exception {
        mvc.perform(
                        get("/jwt/active-sessions")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), "123456"))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE")))
                .andExpect(status().isBadRequest());

    }

    @Test
    @Transactional
    void endSessionId_LegacySessionId_EndsSession() throws Exception {
        JwtTokenInfo jwtTokenInfo = createTokenAndSession("q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3");
        UUID jwtToken = jwtTokenInfo.getJwtUuid();
        String jwtToInvalidate = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), null, "11223344556");

        mvc.perform(
                        post("/jwt/end-session-id")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtToInvalidate))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE"))
                                .content("""
                                        {
                                          "sessionId":"q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3"
                                        }
                                        """)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(cookie().doesNotExist("NOT_REMOVABLE"));

        SessionsEntity expiredLegacySession = sessionsRepository
                .findBySessionId(jwtTokenInfo.getLegacySessionId())
                .orElseThrow(IllegalArgumentException::new);

        assertTrue(expiredLegacySession.getValidTo()
                .isBefore(LocalDateTime.now()));

        mvc.perform(post("/jwt/verify")
                        .content(jwtToInvalidate))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Transactional
    void endSessionId_LegacySessionIdInvalidJwt_ReturnsBadRequest() throws Exception {
        JwtTokenInfo jwtTokenInfo = createTokenAndSession("q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3");

        mvc.perform(
                        post("/jwt/end-session-id")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), "123"))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE"))
                                .content("""
                                        {
                                          "sessionId":"q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3"
                                        }
                                        """)
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Transactional
    void endSession_JwtCookieWithExistingGovssoIdToken_EndsSessionAndRedirectsToGovsso() throws Exception {
        JwtTokenInfo jwtTokenInfo = jwtTokenInfoService.createJwtTokenInfo(UUID.randomUUID(), "q6pzhtnlb0vppk2s1kj8jbz6rw003tvc3", new Timestamp(new Date().getTime() + 1000 * 60 * 30));
        UUID jwtToken = jwtTokenInfo.getJwtUuid();
        String jwtToInvalidate = getJwtTokenString(new Date(), DateUtils.addMinutes(new Date(), 10), jwtSignatureConfig.getIssuer(), jwtToken.toString(), Map.of("govssoSid", GOVSSO_SESSION_ID), SUBJECT);

        sessionsRepository.save(
                createSessionsEntity(
                        jwtTokenInfo.getLegacySessionId(),
                        LocalDateTime.now().plusMinutes(42L),
                        LocalDateTime.now().plusMinutes(42L)
                )
        );
        mockGovssoSession();

        mvc.perform(
                        get("/jwt/end-session?lang=ru")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtToInvalidate))
                                .cookie(new Cookie("NOT_REMOVABLE", "VALUE")))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/html"))
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(nullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), 0))
                .andExpect(cookie().doesNotExist("NOT_REMOVABLE"));

        // Invalidated legacy session should have the validTo in the past
        SessionsEntity expiredLegacySession = sessionsRepository
                .findBySessionId(jwtTokenInfo.getLegacySessionId())
                .orElseThrow(IllegalArgumentException::new);

        assertTrue(expiredLegacySession.getValidTo()
                .isBefore(LocalDateTime.now()));

        mvc.perform(post("/jwt/verify")
                        .content(jwtToInvalidate))
                .andExpect(status().isBadRequest());
    }

    @Test
    void endSession_NoInput_ReturnsEmptyInternalServerErrorResponse() throws Exception {
        mvc.perform(get("/jwt/end-session"))
                .andExpect(status().isInternalServerError())
                .andExpect(header().exists(ERROR_ID_HEADER_KEY))
                .andExpect(cookie().doesNotExist(jwtSignatureConfig.getCookieName()));
    }

    @Test
    void extendJwtSession_EstonianPersonalCode_ReturnsExtendedSession() throws Exception {

        Calendar instance = Calendar.getInstance();
        instance.set(Calendar.MILLISECOND, 0);
        Date tokenCreationDate = instance.getTime();
        instance.add(Calendar.MINUTE, 1);
        Date oldExpirationDate = instance.getTime();
        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());

        UUID oldJwtId = UUID.randomUUID();
        String personalCode = "EE11223344556";
        String jwtTokenString = getJwtTokenString(
            tokenCreationDate,
            oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(),
            Map.of("personalCode", personalCode, "govssoSid", GOVSSO_SESSION_ID), personalCode);

        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, from(oldExpirationDate.toInstant()),
            from(tokenCreationDate.toInstant()), false, null, "not relevant"));

        mockGovssoSession();

        MvcResult mvcResult = mvc.perform(get("/jwt/extend-jwt-session")
                        .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString)))
                .andExpect(status().isOk())
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
                .andReturn();

        Cookie extendedSessionInfo = mvcResult.getResponse()
                .getCookie(jwtSignatureConfig.getCookieName());
        @SuppressWarnings("ConstantConditions")
        UserInfo userInfo = jwtUtils.getUserInfo(extendedSessionInfo.getValue());
        assertThat(userInfo.getLoginExpireDate(), greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())));


        //check that userinfo is updated
        mvc.perform(
                        get("/jwt/userinfo")
                                .cookie(extendedSessionInfo))
                .andExpect(status().isOk())
                .andExpect(jsonPath("loggedInDate", is(tokenCreationDate.getTime())))
                .andExpect(jsonPath("loginExpireDate", greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
                        .getTime())));

        //check that old cookie is blacklisted
        assertThat(jwtTokenInfoRepository.findByJwtUuid(oldJwtId)
                .map(JwtTokenInfo::isBlacklisted), is(Optional.of(true)));

    }

    @Test
    void extendJwtSession_NonEstonianPersonalCode_ReturnsExtendedSession() throws Exception {

        Calendar instance = Calendar.getInstance();
        instance.set(Calendar.MILLISECOND, 0);
        Date tokenCreationDate = instance.getTime();
        instance.add(Calendar.MINUTE, 1);
        Date oldExpirationDate = instance.getTime();
        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());

        UUID oldJwtId = UUID.randomUUID();
        String personalCode = "LT11223344556";
        String jwtTokenString = getJwtTokenString(
            tokenCreationDate,
            oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(),
            Map.of("personalCode", personalCode, "govssoSid", GOVSSO_SESSION_ID), personalCode);

        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, from(oldExpirationDate.toInstant()),
            from(tokenCreationDate.toInstant()), false, null, "not relevant"));

        mockGovssoSession();

        MvcResult mvcResult = mvc.perform(get("/jwt/extend-jwt-session")
                        .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString)))
                .andExpect(status().isOk())
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
                .andReturn();

        Cookie extendedSessionInfo = mvcResult.getResponse()
                .getCookie(jwtSignatureConfig.getCookieName());
        @SuppressWarnings("ConstantConditions")
        UserInfo userInfo = jwtUtils.getUserInfo(extendedSessionInfo.getValue());
        assertThat(userInfo.getLoginExpireDate(), greaterThanOrEqualTo(DateUtils.addMinutes(tokenCreationDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())));


        //check that userinfo is updated
        mvc.perform(
                get("/jwt/userinfo")
                    .cookie(extendedSessionInfo))
            .andExpect(status().isOk())
            .andExpect(jsonPath("loggedInDate", is(tokenCreationDate.getTime())))
            .andExpect(jsonPath("loginExpireDate", greaterThanOrEqualTo(
                DateUtils.addMinutes(tokenCreationDate,
                        legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
                    .getTime())))
            .andExpect(jsonPath("govsso.token", is("access-token")));

        //check that old cookie is blacklisted
        assertThat(jwtTokenInfoRepository.findByJwtUuid(oldJwtId)
                .map(JwtTokenInfo::isBlacklisted), is(Optional.of(true)));

    }

    @Test
    void extendJwtSession_NoCookie_ReturnsBadRequest() throws Exception {
        mvc.perform(get("/jwt/extend-jwt-session"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void extendJwtSession_MissingJwtCookieValue_ReturnsEmptyInternalServerErrorResponse() throws Exception {
        mvc.perform(
                        get("/jwt/extend-jwt-session")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), null)))
                .andExpect(status().isInternalServerError())
                .andExpect(header().exists(ERROR_ID_HEADER_KEY))
                .andExpect(cookie().doesNotExist(jwtSignatureConfig.getCookieName()));
    }

    @Test
    void extendJwtSession_EmptyJwtCookieValue_ReturnsBadRequest() throws Exception {
        mvc.perform(
                        get("/jwt/extend-jwt-session")
                                .cookie(new Cookie(jwtSignatureConfig.getCookieName(), "")))
                .andExpect(status().isBadRequest())
                .andExpect(content().bytes(new byte[]{}))
                .andExpect(cookie().doesNotExist(jwtSignatureConfig.getCookieName()));
    }


    @Test
    void refreshJwtSession_ReturnsExtendedSession() throws Exception {

        Calendar instance = Calendar.getInstance();
        instance.set(Calendar.MILLISECOND, 0);
        Date tokenCreationDate = instance.getTime();
        instance.add(Calendar.MINUTE, 1);
        Date oldExpirationDate = instance.getTime();

        UUID oldJwtId = UUID.randomUUID();
        String jwtTokenString = getJwtTokenString(
                tokenCreationDate,
                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), Collections.singletonMap("personalCode", SUBJECT), SUBJECT);

        sessionsRepository.save(createSessionsEntity(DEFAULT_SESSION_ID_1, LocalDateTime.now(), LocalDateTime.now().plusMinutes(10L)));
        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, from(oldExpirationDate.toInstant()), from(tokenCreationDate.toInstant()), false, null, DEFAULT_SESSION_ID_1));
        String oldRefreshToken = refreshTokenService.create(DEFAULT_SESSION_ID_1);

        queryTokenRefesh(jwtTokenString, oldRefreshToken);

        assertThat(jwtTokenInfoRepository.findByJwtUuid(oldJwtId).map(JwtTokenInfo::isBlacklisted), is(Optional.of(true)));
        assertThat(refreshTokenService.findByToken(oldRefreshToken).isInvalidated(), is(true));

    }

    @Test
    void refreshJwtSession_InvalidRefreshToken_InvalidatesAllSessionRelatedTokens() throws Exception {

        Calendar instance = Calendar.getInstance();
        instance.set(Calendar.MILLISECOND, 0);
        Date tokenCreationDate = instance.getTime();
        instance.add(Calendar.MINUTE, 1);
        Date oldExpirationDate = instance.getTime();

        UUID oldJwtId = UUID.randomUUID();
        String oldJwtTokenString = getJwtTokenString(
                tokenCreationDate,
                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), Collections.singletonMap("personalCode", SUBJECT), SUBJECT);

        sessionsRepository.save(createSessionsEntity(DEFAULT_SESSION_ID_1, LocalDateTime.now(), LocalDateTime.now().plusMinutes(10L)));
        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, from(oldExpirationDate.toInstant()), from(tokenCreationDate.toInstant()), false, null, DEFAULT_SESSION_ID_1));
        String oldRefreshToken = refreshTokenService.create(DEFAULT_SESSION_ID_1);

        MvcResult mvcResult = queryTokenRefesh(oldJwtTokenString, oldRefreshToken);

        Cookie newRefreshCookie = mvcResult.getResponse().getCookie(appRefreshTokenConfig.getCookieName());
        assertNotNull(newRefreshCookie);

        Cookie newJwtToken = mvcResult.getResponse().getCookie(jwtSignatureConfig.getCookieName());
        assertNotNull(newJwtToken);

        JWT newJwt = jwtUtils.decodeJwtAndVerifySignature(newJwtToken.getValue());
        String newJwtId = newJwt.getJWTClaimsSet().getJWTID();

        mvc.perform(post("/jwt/refresh-jwt-session")
                        .cookie(new Cookie(jwtSignatureConfig.getCookieName(), oldJwtTokenString),
                                new Cookie(appRefreshTokenConfig.getCookieName(), oldRefreshToken)))
                .andExpect(status().isBadRequest());

        assertThat(jwtTokenInfoRepository.findByJwtUuid(UUID.fromString(newJwtId)).map(JwtTokenInfo::isBlacklisted), is(Optional.of(true)));
        assertThat(refreshTokenService.findByToken(refreshTokenService.findByToken(newRefreshCookie.getValue()).getValue()).isInvalidated(), is(true));
    }

    @NotNull
    private MvcResult queryTokenRefesh(String jwtTokenString, String oldRefreshToken) throws Exception {
        return mvc.perform(post("/jwt/refresh-jwt-session")
                        .cookie(new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString),
                                new Cookie(appRefreshTokenConfig.getCookieName(), oldRefreshToken)))
                .andExpect(status().isOk())
                .andExpect(cookie().value(jwtSignatureConfig.getCookieName(), is(notNullValue())))
                .andExpect(cookie().maxAge(jwtSignatureConfig.getCookieName(), is(-1)))
                .andExpect(cookie().value(appRefreshTokenConfig.getCookieName(), is(notNullValue())))
                .andReturn();
    }

    @Test
    @Transactional
    void getJwtRepresentableParties_ValidJwtCookie_ReturnsUserRepresentableParties() throws Exception {
        Calendar instance = Calendar.getInstance();
        instance.set(Calendar.MILLISECOND, 0);
        Date tokenCreationDate = instance.getTime();
        instance.add(Calendar.MINUTE, 1);
        Date oldExpirationDate = instance.getTime();
        instance.add(Calendar.MINUTE, legacyPortalIntegrationConfig.getSessionTimeoutMinutes());

        UUID oldJwtId = UUID.randomUUID();
        String personalCode = "EE11223344556";
        Map<String, String> claimsToAdd = Map.of(
                "personalCode", personalCode,
                "firstName", "Eesnimi",
                "lastName", "Perenimi"
        );
        String jwtTokenString = getJwtTokenString(
                tokenCreationDate,
                oldExpirationDate, jwtSignatureConfig.getIssuer(), oldJwtId.toString(), claimsToAdd, personalCode);

        jwtTokenInfoRepository.save(new JwtTokenInfo(oldJwtId, from(oldExpirationDate.toInstant()), from(tokenCreationDate.toInstant()), false, null, "not relevant"));

        when(rightsClient.getRepresentableParties(jwtTokenString, "et"))
                .thenReturn(RightsRepresentablePartiesResponse.builder().representableParties(List.of(
                        RepresentableParty.builder()
                                .id(0L)
                                .type(RepresentableParty.Type.CITIZEN)
                                .code("EE11223344556")
                                .name("Eesnimi Perenimi")
                                .build(),
                        RepresentableParty.builder()
                                .id(14222L)
                                .type(RepresentableParty.Type.BUSINESS)
                                .code("EE70006317")
                                .name("RIA")
                                .build()
                )).status(200).build());

        Cookie jwtCookie = new Cookie(jwtSignatureConfig.getCookieName(), jwtTokenString);

        mvc.perform(get("/jwt/representable-parties")
                        .cookie(jwtCookie))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(content().json("""
                        [
                          {
                            "id": 0,
                            "type": "CITIZEN",
                            "code": "EE11223344556",
                            "name": "Eesnimi Perenimi"
                          },
                          {
                            "id": 14222,
                            "type": "BUSINESS",
                            "code": "EE70006317",
                            "name": "RIA"
                          }
                        ]
                        """));
    }

    @Test
    void getJwtRepresentableParties_NoCookie_ReturnsBadRequest() throws Exception {
        mvc.perform(get("/jwt/representable-parties"))
                .andExpect(status().isBadRequest());
    }


    private SessionsEntity createSessionsEntity(String legacySessionId, LocalDateTime validFrom, LocalDateTime validTo) {
        SessionsEntity sessionsEntity = new SessionsEntity();
        sessionsEntity.setPersonalCode("EE11223344556");
        sessionsEntity.setSessionId(legacySessionId);
        sessionsEntity.setLastModified(LocalDateTime.now());
        sessionsEntity.setValidFrom(validFrom.atOffset(ZoneOffset.UTC)
                .toLocalDateTime());
        sessionsEntity.setValidTo(validTo.atOffset(ZoneOffset.UTC)
                .toLocalDateTime());
        sessionsEntity.setRights("AMETNIK=KODANIK=0=0");
        sessionsEntity.setParams("{{LANG,ee},{XMLHTTP,YES}}");

        return sessionsEntity;
    }

    private void mockGovssoSession() {
        OidcIdToken idToken = new OidcIdToken(
                "abc123", Instant.now(), Instant.now()
                .plus(1, HOURS),
                Map.of("sid", GOVSSO_SESSION_ID,
                        "sub", SUBJECT));
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token", Instant.now());
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now(),
                Instant.now().plusSeconds(15 * 60));
        GovssoSessionEntity govssoSessionEntity = new GovssoSessionEntity(
                GOVSSO_SESSION_ID,
                SerializationUtils.serialize(idToken),
                SerializationUtils.serialize(refreshToken),
                SerializationUtils.serialize(accessToken));
        when(govssoSessionRepository.findById(GOVSSO_SESSION_ID))
                .thenReturn(Optional.of(govssoSessionEntity));
    }

    private JwtTokenInfo createTokenAndSession(String sessionId) {
        JwtTokenInfo jwtTokenInfo = jwtTokenInfoService.createJwtTokenInfo(UUID.randomUUID(), sessionId, new Timestamp(new Date().getTime() + 1000 * 60 * 30));

        sessionsRepository.save(
                createSessionsEntity(
                        jwtTokenInfo.getLegacySessionId(),
                        LocalDateTime.now()
                                .plusMinutes(42L),
                        LocalDateTime.now()
                                .plusMinutes(42L)));
        return jwtTokenInfo;
    }

}
