package ee.eesti.authentication.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.aop.Timed;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.domain.GovssoSession;
import ee.eesti.authentication.domain.RemoveSessionRequest;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.RightsRepresentablePartiesResponse;
import ee.eesti.authentication.domain.SelectRepresentablePartyByCodeRequest;
import ee.eesti.authentication.domain.SessionInfo;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.domain.UserInfoResponseDto;
import ee.eesti.authentication.domain.UserSession;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import ee.eesti.authentication.service.CookieService;
import ee.eesti.authentication.service.GovssoLogoutService;
import ee.eesti.authentication.service.GovssoSessionService;
import ee.eesti.authentication.service.GovssoUpdateSessionService;
import ee.eesti.authentication.service.JwtTokenInfoService;
import ee.eesti.authentication.service.RefreshTokenAuthenticationProvider;
import ee.eesti.authentication.service.RefreshTokenService;
import ee.eesti.authentication.service.RightsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static ee.eesti.authentication.handlers.RestExceptionHandler.ERROR_ID_HEADER_KEY;

/**
 * Controller to handle all JWT related endpoints
 */

@RestController
@Slf4j
@Tag(name = "jwt", description = "Operations pertaining to JWT in Tara Integration module")
@Timed
@RequiredArgsConstructor
public class JwtController {
    private final RefreshTokenService refreshTokenService;

    private final RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider;

    private final JwtSignatureConfig jwtSignatureConfig;

    private final JwtUtils jwtUtils;

    private final JwtTokenInfoRepository jwtTokenInfoRepository;

    private final JwtTokenInfoService jwtTokenInfoService;

    private final SessionsRepository sessionsRepository;

    private final RightsService rightsService;

    private final CookieService cookieService;

    private final GovssoSessionService govssoSessionService;

    private final GovssoLogoutService govssoLogoutService;

    private final GovssoUpdateSessionService govssoUpdateSessionService;

    private String publicKey;

    private static final ResponseEntity<Void> emptyOkResponse = ResponseEntity.ok()
            .build();

    private static final ResponseEntity<?> badRequest = ResponseEntity.badRequest()
            .build();


    /**
     * load public key (will be used by various methods of this controller) from KeyStore
     */
    @PostConstruct
    public void postConstruct() {
        publicKey = loadPublicKey();
    }

    /**
     * @return public key
     */
    @Operation(summary = "Obtain the JWT verification key")
    @ApiResponse(responseCode = "200", description = "Verification key in PEM format")
    @GetMapping(path = "/v2/jwt/verification-key", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getJwtVerificationKeyV2() {
        return publicKey;
    }

    /**
     * @return public key
     */
    @Deprecated
    @Operation(summary = "Obtain the JWT verification key")
    @ApiResponse(responseCode = "200", description = "Verification key in PEM format")
    @GetMapping(path = "/jwt/verification-key", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getJwtVerificationKey() {
        return publicKey;
    }

    private String loadPublicKey() {
        log.debug("loading verification key");
        KeyStore jwtSignKeyStore;
        try {
            jwtSignKeyStore = KeyStore.getInstance(jwtSignatureConfig.getKeyStoreType());
            jwtSignKeyStore.load(jwtSignatureConfig.getKeyStore()
                    .getInputStream(), jwtSignatureConfig.getKeyStorePassword()
                    .toCharArray());

            Certificate certificate = jwtSignKeyStore.getCertificate(jwtSignatureConfig.getKeyAlias());

            return String.format("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
                    Base64.getMimeEncoder(64, new byte[]{'\n'})
                            .encodeToString(certificate.getPublicKey()
                                    .getEncoded()));
        } catch (Exception e) {
            log.error("cannot load public key", e);
            throw new IllegalStateException(e);
        }
    }

    /**
     * @param jwtTokenToCheck JWT to verify
     * @return response with status 200 if verification successful and with status 400 if not
     */
    @Operation(summary = "Verify the JWT")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content, description = "Verification successful"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Verification failed")
    })
    @PostMapping(value = "/v2/jwt/verify")
    public ResponseEntity<?> verifyTokenV2(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "JWT to verify",
                    // The same can be achieved with @PostMapping(consumes) but that would break backwards compatibility
                    content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE, schema = @Schema(implementation = String.class)))
            @RequestBody String jwtTokenToCheck
    ) {
        boolean valid = jwtUtils.getUserInfo(jwtTokenToCheck) != null;

        return valid
                ? emptyOkResponse
                : ResponseEntity.badRequest()
                .build();
    }

    /**
     * @param jwtTokenToCheck JWT to verify
     * @return response with status 200 if verification successful and with status 400 if not
     */
    @Deprecated
    @Operation(summary = "Verify the JWT")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content, description = "Verification successful"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Verification failed")
    })
    @PostMapping(value = "/jwt/verify")
    public ResponseEntity<?> verifyToken(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "JWT to verify",
                    // The same can be achieved with @PostMapping(consumes) but that would break backwards compatibility
                    content = @Content(mediaType = MediaType.TEXT_PLAIN_VALUE, schema = @Schema(implementation = String.class)))
            @RequestBody String jwtTokenToCheck
    ) {
        boolean valid = jwtUtils.getUserInfo(jwtTokenToCheck) != null;

        return valid
                ? emptyOkResponse
                : ResponseEntity.badRequest()
                .build();
    }

    /**
     * @param jwtFromCookie JWT from cookie
     * @return if successful returns user's info as decoded from JWT acquired from request cookie
     */
    @Operation(
            summary = "Decode the JWT into userInfo",
            description = "Validates the JWT and in case of successful validation decodes the token into user info")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(schema = @Schema(implementation = UserInfo.class), mediaType = MediaType.APPLICATION_JSON_VALUE, examples = {
                    @ExampleObject(value = """
                            {
                              "personalCode": "EE60001019906",
                              "authenticatedAs": "EE60001019906",
                              "hash": "3440fb13e3804cac8374a4baf0e50b20eb61281b73d24a5fbd07e2b987ec5a34",
                              "firstName": "MARY ÄNN",
                              "lastName": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
                              "loggedInDate": 1646200354000,
                              "loginExpireDate": 1646202154000,
                              "authMethod": "mID",
                              "acr": "substantial",
                              "representedParty": {
                                "id": 0,
                                "type": "CITIZEN",
                                "code": "EE60001019906"
                              },
                              "govsso": {
                                "sessionId": "31988ca0-47b1-4cb5-b919-0fadc552ac8d",
                                "expiration": 1646201254
                              },
                              "currentTimestamp": 1646200354,
                              "fullName": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                            }""", name = "Representable party - CITIZEN"),
                    @ExampleObject(value = """
                                                {
                              "personalCode": "EE60001019906",
                              "authenticatedAs": "EE60001019906",
                              "hash": "3440fb13e3804cac8374a4baf0e50b20eb61281b73d24a5fbd07e2b987ec5a34",
                              "firstName": "MARY ÄNN",
                              "lastName": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
                              "loggedInDate": 1646200354000,
                              "loginExpireDate": 1646202154000,
                              "authMethod": "mID",
                              "acr": "high",
                              "representedParty": {
                                "id": 101712,
                                "type": "BUSINESS",
                                "code": "EE11111111"
                              },
                              "govsso": {
                                "sessionId": "31988ca0-47b1-4cb5-b919-0fadc552ac8d",
                                "expiration": 1646201254
                              },
                              "currentTimestamp": 1646200354,
                              "fullName": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                            }
                            """, name = "Representable party - BUSINESS")}), description = "decoding done successfully"),
            @ApiResponse(responseCode = "400", description = "decoding failed", content = @Content)
    })
    @GetMapping(path = "/v2/jwt/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> decodeJwtFromCookieV2(@Parameter(description = "JWT") @CookieValue("${jwt-integration.signature.cookie-name}") String jwtFromCookie) {
        if (!StringUtils.hasText(jwtFromCookie)) {
            log.debug("cookie is invalid, cookie value: {}", jwtFromCookie);
            return badRequest;
        }
        UserSession userSession = jwtUtils.getUserSession(jwtFromCookie);
        if (userSession == null) {
            log.debug("User session cannot be parsed from cookie value: {} ", jwtFromCookie);
            return badRequest;
        }
        return ResponseEntity.ok(UserInfoResponseDto.from(userSession));
    }

    /**
     * @param jwtFromCookie JWT from cookie
     * @return if successful returns user's info as decoded from JWT acquired from request cookie
     */
    @Deprecated
    @Operation(
            summary = "Decode the JWT into userInfo",
            description = "Validates the JWT and in case of successful validation decodes the token into user info")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(schema = @Schema(implementation = UserInfo.class), mediaType = MediaType.APPLICATION_JSON_VALUE, examples = {
                    @ExampleObject(value = """
                            {
                              "personalCode": "EE60001019906",
                              "authenticatedAs": "EE60001019906",
                              "hash": "3440fb13e3804cac8374a4baf0e50b20eb61281b73d24a5fbd07e2b987ec5a34",
                              "firstName": "MARY ÄNN",
                              "lastName": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
                              "loggedInDate": 1646200354000,
                              "loginExpireDate": 1646202154000,
                              "authMethod": "mID",
                              "acr": "substantial",
                              "representedParty": {
                                "id": 0,
                                "type": "CITIZEN",
                                "code": "EE60001019906"
                              },
                              "govsso": {
                                "sessionId": "31988ca0-47b1-4cb5-b919-0fadc552ac8d",
                                "expiration": 1646201254
                              },
                              "currentTimestamp": 1646200354,
                              "fullName": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                            }""", name = "Representable party - CITIZEN"),
                    @ExampleObject(value = """
                                                {
                              "personalCode": "EE60001019906",
                              "authenticatedAs": "EE60001019906",
                              "hash": "3440fb13e3804cac8374a4baf0e50b20eb61281b73d24a5fbd07e2b987ec5a34",
                              "firstName": "MARY ÄNN",
                              "lastName": "O’CONNEŽ-ŠUSLIK TESTNUMBER",
                              "loggedInDate": 1646200354000,
                              "loginExpireDate": 1646202154000,
                              "authMethod": "mID",
                              "acr": "high",
                              "representedParty": {
                                "id": 101712,
                                "type": "BUSINESS",
                                "code": "EE11111111"
                              },
                              "govsso": {
                                "sessionId": "31988ca0-47b1-4cb5-b919-0fadc552ac8d",
                                "expiration": 1646201254
                              },
                              "currentTimestamp": 1646200354,
                              "fullName": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                            }
                            """, name = "Representable party - BUSINESS")}), description = "decoding done successfully"),
            @ApiResponse(responseCode = "400", description = "decoding failed", content = @Content)
    })
    @GetMapping(path = "/jwt/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> decodeJwtFromCookie(@Parameter(description = "JWT") @CookieValue("${jwt-integration.signature.cookie-name}") String jwtFromCookie) {
        if (!StringUtils.hasText(jwtFromCookie)) {
            log.debug("cookie is invalid, cookie value: {}", jwtFromCookie);
            return badRequest;
        }
        UserSession userSession = jwtUtils.getUserSession(jwtFromCookie);
        if (userSession == null) {
            log.debug("User session cannot be parsed from cookie value: {} ", jwtFromCookie);
            return badRequest;
        }
        return ResponseEntity.ok(UserInfoResponseDto.from(userSession));
    }

    @Operation(
            summary = "Obtain user representable parties",
            description = "Validates the JWT and in case of successful validation returns user representable parties")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(array = @ArraySchema(schema = @Schema(implementation = RepresentableParty.class)), examples = {
                    @ExampleObject(value = """
                            [
                              {
                                "id": 0,
                                "type": "CITIZEN",
                                "code": "EE60001019906",
                                "name": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                              },
                              {
                                "id": 101712,
                                "type": "BUSINESS",
                                "code": "EE11111111",
                                "name": "Ettevõte AS"
                              }
                            ]
                            """)}), description = "Getting representable parties successful"),
            @ApiResponse(responseCode = "240", description = "Response code if Pääsuke service fails, but user can still represent himself.",
                    headers = {@Header(name = "Rig-Error-Id", description = "UUID of the logged error")},
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RepresentableParty.class)), examples = {
                            @ExampleObject(value = """
                                    [
                                      {
                                        "type": "CITIZEN",
                                        "code": "EE60001019906",
                                        "name": "MARY ÄNN O’CONNEŽ-ŠUSLIK TESTNUMBER"
                                      }
                                    ]
                                    """)})),
            @ApiResponse(responseCode = "400", content = @Content, description = "Getting representable parties failed")
    })
    @GetMapping(value = "/jwt/representable-parties", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getJwtRepresentableParties(
            @Parameter(description = "JWT")
            @CookieValue(value = "${jwt-integration.signature.cookie-name}") String jwtFromCookie,
            @Parameter(schema = @Schema(allowableValues = {"et", "en", "ru"}))
            @RequestParam(value = "lang", required = false, defaultValue = "et") String language
    ) {
        UserInfo userInfoFromJwt = jwtUtils.getUserInfo(jwtFromCookie);
        if (userInfoFromJwt == null) {
            return badRequest;
        }
        RightsRepresentablePartiesResponse rightsRepresentablePartiesResponse = rightsService.getRepresentableParties(jwtFromCookie, language);
        ResponseEntity.BodyBuilder bodyBuilder = ResponseEntity.status(rightsRepresentablePartiesResponse.getStatus());
        if (org.apache.commons.lang3.StringUtils.isNotBlank(rightsRepresentablePartiesResponse.getErrorId())) {
            bodyBuilder.header(ERROR_ID_HEADER_KEY, rightsRepresentablePartiesResponse.getErrorId());
        }
        return bodyBuilder.body(rightsRepresentablePartiesResponse.getRepresentableParties());
    }


    @Operation(
            summary = "Select representable party",
            description = """             
                    Validates the JWT and that user is allowed to select the requested representable party. In case of
                    successful validation:
                    1. Invalidates the provided JWT and outputs a new (extended with selected representable party) JWT
                    2. Extends the legacy session
                    """)
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    headers = @Header(name = "Set-Cookie", schema = @Schema(example = "JWTTOKEN=<Encoded JWT>", type = "string"), description = "JWT with selected representable party", required = true),
                    content = @Content,
                    description = "Selecting representable party successful"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Selecting representable party failed")
    })
    @PostMapping(value = "/jwt/select-representable-party-by-code", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> selectJwtSessionRepresentablePartyByCode(
            @Parameter(description = "JWT")
            @CookieValue("${jwt-integration.signature.cookie-name}") String jwtFromCookie,
            @Valid @RequestBody SelectRepresentablePartyByCodeRequest selectPartyRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            String newSerializedJwt = rightsService.selectRepresentativeByCode(
                    jwtFromCookie, selectPartyRequest, request, response);
            ResponseEntity<Void> responseEntity = govssoUpdateSessionService.updateGovssoSession(newSerializedJwt, response);
            return responseEntity;
        } catch (Exception e) {
            return badRequest;
        }
    }

    /**
     * @param jwtFromCookie JWT from cookie
     * @param request       incoming request
     * @param response      current response
     * @return returns 200 status response regardless if extending the cookie was successful or not
     */
    @Operation(
            summary = "Extend session",
            description = """
                    Validates the JWT and that represented party is not revoked. In case of successful validation:
                    1. Invalidates the provided JWT and outputs a new (extended) JWT
                    2. Extends the legacy session""")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    headers = @Header(name = "Set-Cookie", schema = @Schema(example = "JWTTOKEN=<Encoded JWT>", type = "string"), description = "Extended JWT", required = true),
                    content = @Content, description = "JWT extended successfully"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Extending the JWT failed"),
            @ApiResponse(responseCode = "403", content = @Content, description = "Extending the JWT forbidden")
    })
    @GetMapping(value = "/jwt/extend-jwt-session")
    public ResponseEntity<?> extendJwtSession(
            @Parameter(description = "JWT")
            @CookieValue(name = "${jwt-integration.signature.cookie-name}") String jwtFromCookie,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        UserInfo userInfoFromJwt = jwtUtils.getUserInfo(jwtFromCookie);
        if (userInfoFromJwt == null) {
            return badRequest;
        }
        String oldJwtId;
        try {
            SignedJWT parse = SignedJWT.parse(jwtFromCookie);
            oldJwtId = parse.getJWTClaimsSet()
                    .getJWTID();
        } catch (ParseException e) {
            log.error("cannot parse JWT uid. ");
            throw new IllegalStateException(e);
        }

        try {
            JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
                    .findById(UUID.fromString(oldJwtId))
                    .orElseThrow(() -> new IllegalArgumentException("old jwt token info is not found for blacklisting"));

            if (!rightsService.hasRepresentableParty(userInfoFromJwt, jwtFromCookie)) {
                log.warn("User no longer allowed to represent party code: {}", userInfoFromJwt.getRepresentedParty().getCode());
                return new ResponseEntity<>(HttpStatus.FORBIDDEN);
            }

            jwtTokenInfoService.blacklist(jwtTokenInfo);
        } catch (Exception e) {
            log.error("exception in blacklisting old token before extension session", e);
            throw new RuntimeException(e);
        }

        String serializedJwt = jwtTokenInfoService.extendSessionObtainedFromJwt(
                oldJwtId, userInfoFromJwt, request, response);
        return govssoUpdateSessionService.updateGovssoSession(serializedJwt, response);
    }

    /**
     * @param jwtFromCookie          JWT from cookie
     * @param refreshTokenFromCookie Refresh token from cookie
     * @param request                incoming request
     * @param response               current response
     * @return returns 200 status response regardless if extending the cookie was successful or not
     */
    @Operation(
            summary = "Refresh session",
            description = """
                    Validates the JWT and that represented party is not revoked. In case of successful validation:
                    1. Invalidates the provided JWT and outputs a new (extended) JWT
                    2. Invalidates the provided Refresh token and outputs a new (extended) Refresh token
                    """)
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    headers = @Header(name = "Set-Cookie", schema = @Schema(example = "JWTTOKEN=<Encoded JWT>", type = "string"), description = "Extended JWT", required = true),
                    content = @Content, description = "JWT extended successfully"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Extending the JWT failed"),
            @ApiResponse(responseCode = "403", content = @Content, description = "Extending the JWT forbidden")
    })
    @PostMapping(value = "/jwt/refresh-jwt-session")
    public ResponseEntity<?> refreshJwtSession(
            @Parameter(description = "JWT")
            @CookieValue(name = "${jwt-integration.signature.cookie-name}") String jwtFromCookie,
            @Parameter(description = "RT")
            @CookieValue(name = "RT", required = false) String refreshTokenFromCookie,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            refreshTokenAuthenticationProvider.authenticate(refreshTokenFromCookie, jwtFromCookie, request, response);
        } catch (AuthenticationException e) {
            return badRequest;
        }
        return emptyOkResponse;
    }

    @Operation(
            summary = "End session",
            description = """
                    When JWT is provided:
                    1. Validates the JWT signature (but not validity period, because logout must succeed also with an
                    expired JWT)
                    2. Clears user cache
                    3. Invalidates the JWT
                    4. Invalidates the legacy session
                    5. Removes configured session cookies
                    6. If GovSSO ID Token exists in store, redirects to GovSSO logout endpoint. Otherwise redirects to
                    portal post-logout page.
                    """)
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content)
    })
    @GetMapping("/jwt/end-session")
    @Transactional
    public ResponseEntity<?> endSession(
            @Parameter(description = "JWT")
            @CookieValue(name = "${jwt-integration.signature.cookie-name}", required = false) String jwtFromCookie,
            @RequestParam(name = "lang", required = false) @Pattern(regexp = "^(et|en|ru)$") String language,
            @RequestParam(name = "logout_callback_url", required = false) String postLogoutRedirectUri,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        JWT jwt = jwtUtils.decodeJwtAndVerifySignature(jwtFromCookie);
        if (jwt == null) {
            throw new RuntimeException("Invalid TIMUR JWT cookie");
        }

        rightsService.evictUserCache(jwtFromCookie);

        JWTClaimsSet jwtClaimsSet;
        try {
            jwtClaimsSet = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid TIMUR JWT cookie", e);
        }
        jwtTokenInfoRepository.findById(UUID.fromString(jwtClaimsSet.getJWTID()))
                .ifPresent(jwtTokenInfo -> {
                    jwtTokenInfoService.blacklist(jwtTokenInfo);
                    refreshTokenService.invalidateByLegacySessionId(jwtTokenInfo.getLegacySessionId());
                });
        Optional.ofNullable(request.getSession(false))
                .ifPresent(HttpSession::invalidate);

        cookieService.getDeletableCookies(request.getCookies())
                .forEach(response::addCookie);

        String govssoSessionId = (String) jwtClaimsSet.getClaim("govssoSid");
        Optional<GovssoSession> govssoSession = govssoSessionService.findByIdIncludingExpired(govssoSessionId);

        if (govssoSession.isPresent()) {
            String htmlResponseString = govssoLogoutService.logoutWithGovssoSession(govssoSession.get(), language, postLogoutRedirectUri);
            return ResponseEntity.status(HttpStatus.OK)
                    .contentType(MediaType.TEXT_HTML)
                    .body(htmlResponseString);
        }

        String redirectUrl = govssoLogoutService.logoutWithoutGovssoSession(language, postLogoutRedirectUri);
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectUrl))
                .build();
    }


    @Operation(
            summary = "End session by id")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content)
    })
    @PostMapping(value = "/jwt/end-session-id", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> endSessionByLegacyId(
            @Parameter(description = "JWT")
            @CookieValue(name = "${jwt-integration.signature.cookie-name}", required = false) String jwtFromCookie,
            @Valid @RequestBody RemoveSessionRequest removeSessionRequest
    ) {
        JWT jwt = jwtUtils.decodeJwtAndVerifySignature(jwtFromCookie);
        if (jwt == null) {
            return badRequest;
        }
        jwtTokenInfoRepository.findAllByLegacySessionId(removeSessionRequest.getSessionId())
                .ifPresent(jwtTokens -> jwtTokens.forEach(jwtTokenInfoService::blacklist));

        return ResponseEntity.status(HttpStatus.OK)
                .build();
    }

    @Operation(
            summary = "Obtain user active sessions",
            description = "Validates the JWT and in case of successful validation returns user active sessions")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content(array = @ArraySchema(schema = @Schema(implementation = SessionInfo.class)), examples = {
                    @ExampleObject(value = """
                             [
                              {
                                  "id": 159214160,
                                  "channel": "M-ID",
                                  "sessionId": "5f7be5867f5349ec846cb76fb536a6ef",
                                  "personalCode": "60001017869",
                                  "authenticatedAs": "EE60001017869",
                                  "hash": "1de0b5b6e02945aa929e9d9a12f671cafdcdda1dfe7a444e9d779357a66be79e",
                                  "validFrom": "2023-08-15T08:43:56.546836",
                                  "validTo": "2023-08-15T10:00:50.607",
                                  "givenname": "EID2016",
                                  "surname": "TESTNUMBER",
                                  "params": "{{LANG, ee},{XMLHTTP,YES}}",
                                  "created": "2023-08-15T08:43:56.59797",
                                  "lastModified": "2023-08-15T09:30:50.61341",
                                  "ip": "172.31.0.12",
                                  "browser": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
                                  "username": "-",
                                  "loginLevel": "40",
                                  "mobileNumber": "+37268000769",
                                  "certificateType": null,
                                  "current": false
                              }
                            ]
                            
                            """)}), description = "Getting sessions list successfully!"),
            @ApiResponse(responseCode = "400", content = @Content, description = "Getting sessions failed!")
    })
    @GetMapping(value = "/jwt/active-sessions", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getJwtActiveSessions(
            @Parameter(description = "JWT")
            @CookieValue(value = "${jwt-integration.signature.cookie-name}") String jwtFromCookie) {
        UserInfo userInfoFromJwt = jwtUtils.getUserInfo(jwtFromCookie);
        if (userInfoFromJwt == null) {
            return badRequest;
        }
        List<SessionsEntity> sessions = sessionsRepository.findAllByValidToAfterAndAuthenticatedAs(LocalDateTime.now(), userInfoFromJwt.getAuthenticatedAs());
        String oldJwtId;
        try {
            SignedJWT parse = SignedJWT.parse(jwtFromCookie);
            oldJwtId = parse.getJWTClaimsSet()
                    .getJWTID();

            JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
                    .findById(UUID.fromString(oldJwtId))
                    .orElseThrow(() -> new IllegalArgumentException("old jwt token info is not found for blacklisting"));

            for (SessionsEntity session : sessions) {
                if (Objects.equals(session.getSessionId(), jwtTokenInfo.getLegacySessionId())) {
                    session.setCurrent(true);
                    break;
                }
            }

        } catch (Exception e) {
            log.error("Failure while changing representable party", e);
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok(sessions.stream().map(SessionInfo::from).toList());
    }
}
