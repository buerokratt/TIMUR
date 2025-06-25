package ee.eesti.authentication.configuration;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.configuration.govsso.GovssoRefreshTokenTokenResponseClient;
import ee.eesti.authentication.constant.EidasLevelOfAssurance;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.repository.GovssoSessionRepository;
import ee.eesti.authentication.repository.entity.GovssoSessionEntity;
import ee.eesti.authentication.service.GovssoAccessTokenService;
import ee.eesti.authentication.service.JwtTokenInfoService;
import jakarta.servlet.http.Cookie;
import lombok.SneakyThrows;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
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
import org.springframework.session.Session;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.sql.Date;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.HOURS;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SecurityConfigurationTest extends AbstractSpringBasedTest {

    public static final String AUTHORIZATION_ENDPOINT = "/oauth2/authorization/govsso";
    public static final String REFRESH_ENDPOINT = "/oauth2/refresh/govsso";
    private static final String USER_AUTHORIZATION_URI = "https://govsso.test/oidc/authorize";
    public static final String GOVSSO_SESSION_ID = "govsso-session-id-1234";
    public static final String SUBJECT = "EE12345678901";
    public static final String AUTHORIZED_PARTY_CLAIM_NAME = "azp";

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
    private JwtSignatureConfig signatureConfig;

    @Autowired
    private JWSSigner jwsSigner;

    @MockBean
    private GovssoSessionRepository govssoSessionRepository;

    @Autowired
    private JwtTokenInfoService jwtTokenInfoService;

    @Autowired
    private RedisSessionRepository redisSessionRepository;


    @Test
    void get_NoPath_RedirectsToLogin() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://example.org"));
    }

    @BeforeEach
    void setUp() throws Exception {
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
        claims.put(IdTokenClaimNames.ACR, EidasLevelOfAssurance.SUBSTANTIAL.getValue());
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
    void callbackUrl_NotAllowed_ReturnsBadRequest() throws Exception {
        mvc.perform(get("%s?callback_url={callback}".formatted(AUTHORIZATION_ENDPOINT), "https://not.allowed.eesti.ee/callback"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> assertThat(result.getResponse().getErrorMessage(), is("Callback url is not in allowed list")));
    }

    @Test
    void callbackUrl_Allowed_IsRedirected() throws Exception {
        mvc.perform(get("%s?callback_url={callback}".formatted(AUTHORIZATION_ENDPOINT), "https://example.com"))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl(), startsWith(USER_AUTHORIZATION_URI)));
    }

    @ParameterizedTest
    @CsvSource({
            "''                      ,substantial",
            "&acr_values=other       ,substantial",
            "&acr_values=low         ,substantial",
            "&acr_values=substantial ,substantial",
            "&acr_values=SuBStaNtiaL ,substantial",
            "&acr_values=high        ,high",
            "&acr_values=HiGh        ,high"
    })
    void authenticate_InitiatedWithAcrValues_RedirectsToCallbackUrlWithAcrValues(String urlParameters, String expecedAcr) throws Exception {
        String expectedRedirectUrl = "https://example.com";
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT + "?callback_url=".concat(expectedRedirectUrl) + urlParameters);

        assertEquals(1, taraFirstStep.extractedQueryParams.get("acr_values").size());
        assertEquals(expecedAcr, taraFirstStep.extractedQueryParams.get("acr_values").get(0));
    }

    @Test
    void authenticate_InitiatedWithCallbackUrl_RedirectsToCallbackUrl() throws Exception {
        String expectedRedirectUrl = "https://example.com";
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT + "?callback_url=".concat(expectedRedirectUrl));

        Cookie sessionCookie = taraFirstStep.redirectToTaraMockResult.getResponse().getCookie("SESSION");
        assertNotNull(sessionCookie);

        mvc.perform(get("/authenticate")
                .cookie(sessionCookie)
                .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
                .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
                .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
                .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
                .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
                .param("code", "openid"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(expectedRedirectUrl))
        ;
    }

    @Test
    void authenticate_InitiatedWithCallbackUrl_UserCancelsAuthentication() throws Exception {
        String expectedRedirectUrl = "https://example.com";
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT + "?callback_url=".concat(expectedRedirectUrl));

        Cookie sessionCookie = taraFirstStep.redirectToTaraMockResult.getResponse().getCookie("SESSION");
        assertNotNull(sessionCookie);

        mvc.perform(get("/authenticate")
                .cookie(sessionCookie)
                .param("error", "user_cancel")
                .param("error_description", "User+canceled+the+authentication+process.")
                .param("state", taraFirstStep.extractedQueryParams.get("state").get(0)))

                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://example.org")) // frontpage
        ;
    }

    @Test
    void authenticate_InitiatedNotFromLegacyPortalAndWithoutCallbackUrl_ReturnsJwt() throws Exception {
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT);

        Cookie sessionCookie = taraFirstStep.redirectToTaraMockResult.getResponse().getCookie("SESSION");
        assertNotNull(sessionCookie);

        mvc.perform(get("/authenticate")
                .cookie(sessionCookie)
                .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
                .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
                .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
                .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
                .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
                .param("code", "openid"))
                .andExpect(status().isOk())
                .andExpect(result -> {

                    SignedJWT signedJWT = SignedJWT.parse(result.getResponse().getContentAsString());
                    boolean verify = signedJWT.verify(new RSASSAVerifier(getRSAKey(signatureConfig)));
                    assertThat(verify, is(true));
                })
        ;
    }

    @ParameterizedTest
    @CsvSource({
            "&scope=offline_access  ,true ",
            "&scope=                ,false",
            "''                     ,false",
    })
    void authenticate_OfflineAccessScope_AddsAuthorizedPartyClaim(String scope, boolean storesAuthorizedPartyClaim) throws Exception {
        HttpHeaders httpHeaders = new HttpHeaders();
        String expectedRedirectUrl = "https://example.com";
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT
                + "?callback_url=".concat(expectedRedirectUrl)
                + scope, null, httpHeaders);

        Cookie sessionCookie = taraFirstStep.redirectToTaraMockResult.getResponse().getCookie("SESSION");
        assert sessionCookie != null;

        mvc.perform(get("/authenticate")
                        .cookie(sessionCookie)
                        .param("state", taraFirstStep.extractedQueryParams.get("state").get(0))
                        .param("response_type", taraFirstStep.extractedQueryParams.get("response_type").get(0))
                        .param("scope", taraFirstStep.extractedQueryParams.get("scope").get(0))
                        .param("client_id", taraFirstStep.extractedQueryParams.get("client_id").get(0))
                        .param("redirect_uri", taraFirstStep.extractedQueryParams.get("redirect_uri").get(0))
                        .param("code", "openid"))
                .andExpect(result -> {
                    SignedJWT signedJWT = SignedJWT.parse(Objects.requireNonNull(result.getResponse().getCookie("JWTTOKEN")).getValue());
                    assertEquals(Objects.nonNull(signedJWT.getJWTClaimsSet().getClaim(AUTHORIZED_PARTY_CLAIM_NAME)), storesAuthorizedPartyClaim);
                })
        ;
    }


    @ParameterizedTest
    @CsvSource({
            "offline_access         , true  , offline_access",
            "offline_access mobile  , true  , offline_access",
            "                       , false ,               ",
    })
    void authenticate_InitiatedWithOfflineAccessScope_StoresOfflineAccessScope(String requestedScope, boolean storedScope, String storedScopeValue) throws Exception {
        String expectedRedirectUrl = "https://example.com";
        HttpHeaders httpHeaders = new HttpHeaders();
        TaraAuthTestHelper taraFirstStep = getTaraFirstAuthStepDone(AUTHORIZATION_ENDPOINT
                + "?callback_url=".concat(expectedRedirectUrl)
                + "&scope=" + requestedScope, null, httpHeaders);

        Cookie sessionCookie = taraFirstStep.redirectToTaraMockResult.getResponse().getCookie("SESSION");
        assert sessionCookie != null;
        Session session = redisSessionRepository.findById(new String(Base64.getDecoder().decode(sessionCookie.getValue())));
        assertNotNull(session);
        assertEquals(Objects.nonNull(session.getAttribute(SCOPE)), storedScope);
        if (Objects.isNull(session.getAttribute(SCOPE))) {
            assertThat(session.getAttribute(SCOPE), is(storedScopeValue));
        }
    }

    @Test
    void authenticate_UpdatingGovssoSession_ReturnsNothing() throws Exception {
        Cookie timurJwtCookie = createTimurJwt();
        mockGovssoSession();
        mvc.perform(post(REFRESH_ENDPOINT)
                        .cookie(timurJwtCookie))
                .andExpect(cookie().doesNotExist(signatureConfig.getCookieName()))
                .andExpect(status().isOk());
    }

    @Test
    void authenticate_UpdatingGovssoSessionWithoutExistingSession_Fails() throws Exception {
        mvc.perform(post(REFRESH_ENDPOINT))
                .andExpect(status().is4xxClientError());
    }

    private void mockGovssoSession() {
        OidcIdToken idToken = new OidcIdToken(
                "ignored", Instant.now(), Instant.now().plus(1, HOURS),
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

    @SneakyThrows
    private Cookie createTimurJwt() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(SUBJECT)
                .notBeforeTime(Date.from(Instant.EPOCH))
                .expirationTime(Date.from(Instant.now().plus(1, HOURS)))
                .issueTime(Date.from(Instant.now()))
                .issuer(signatureConfig.getIssuer())
                .claim("govssoSid", GOVSSO_SESSION_ID)
                .claim("representedParty", Map.of(
                        "id", 0L,
                        "type", RepresentableParty.Type.CITIZEN,
                        "code", "personalCode"
                ))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.PS256), claimsSet);
        signedJWT.sign(jwsSigner);

        jwtTokenInfoService.createJwtTokenInfo(
                UUID.fromString(claimsSet.getJWTID()),
                "legacySessionId",
                new Timestamp(claimsSet.getExpirationTime().getTime()));

        return new Cookie(signatureConfig.getCookieName(), signedJWT.serialize());
    }

    private TaraAuthTestHelper getTaraFirstAuthStepDone(String authorizationUrl) throws Exception {
        return getTaraFirstAuthStepDone(authorizationUrl, null, null);
    }

    private TaraAuthTestHelper getTaraFirstAuthStepDone(String authorizationUrl, Cookie timurJwt, HttpHeaders customHeader) throws Exception {
        //redirect to tara
        MockHttpServletRequestBuilder mockHttpServletRequestBuilder = get(authorizationUrl);
        if (timurJwt != null) {
            mockHttpServletRequestBuilder.cookie(timurJwt);
        }
        if (customHeader != null) {
            mockHttpServletRequestBuilder.headers(customHeader);
        }

        MvcResult redirectToTaraMockResult = mvc
                .perform(mockHttpServletRequestBuilder)
                .andExpect(status().is3xxRedirection())
                .andReturn();

        //fake tara reports back a token
        String redirectedUrl = redirectToTaraMockResult.getResponse().getRedirectedUrl();

        assertNotNull(redirectedUrl);

        Map<String, List<String>> stringListMap = extractQueryParams(redirectedUrl.substring(redirectedUrl.lastIndexOf('?') + 1));

        return new TaraAuthTestHelper(redirectToTaraMockResult, stringListMap);
    }

    private Map<String, List<String>> extractQueryParams(String query) {
        return Arrays.stream(query.split("&"))
                .map(this::splitQueryParameter)
                .collect(Collectors.groupingBy(AbstractMap.SimpleImmutableEntry::getKey, LinkedHashMap::new, mapping(Map.Entry::getValue, toList())));
    }

    private AbstractMap.SimpleImmutableEntry<String, String> splitQueryParameter(String it) {

        try {
            it = URLDecoder.decode(it, UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        final int idx = it.indexOf("=");
        final String key = idx > 0 ? it.substring(0, idx) : it;
        final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;

        return new AbstractMap.SimpleImmutableEntry<>(key, value);
    }

    private static class TaraAuthTestHelper {
        final MvcResult redirectToTaraMockResult;
        final Map<String, List<String>> extractedQueryParams;

        public TaraAuthTestHelper(MvcResult redirectToTaraMockResult, Map<String, List<String>> extractedQueryParams) {
            this.redirectToTaraMockResult = redirectToTaraMockResult;
            this.extractedQueryParams = extractedQueryParams;
        }
    }

    public static RSAKey getRSAKey(JwtSignatureConfig signatureConfig) throws Exception {
        KeyStore signKeyStore = KeyStore.getInstance(signatureConfig.getKeyStoreType());
        signKeyStore.load(signatureConfig.getKeyStore().getInputStream(), signatureConfig.getKeyStorePassword().toCharArray());

        JWKSet jwkSet = JWKSet.load(signKeyStore, name -> signatureConfig.getKeyStorePassword().toCharArray());
        JWK signKey = jwkSet.getKeyByKeyId(signatureConfig.getKeyAlias());

        return (RSAKey) signKey;
    }
}
