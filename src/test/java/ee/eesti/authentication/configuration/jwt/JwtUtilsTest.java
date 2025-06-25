package ee.eesti.authentication.configuration.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.service.JwtTokenInfoService;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwtUtilsTest extends AbstractSpringBasedTest {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private JwtTokenInfoService jwtTokenInfoService;

    @Autowired
    private LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;

    @Autowired
    private JwtSignatureConfig jwtSignatureConfig;

    @Test
    void getUserSession_SignedAndRegistered_ReturnsSession() throws ParseException {
        UserInfo userInfo = new UserInfo();
        userInfo.setRepresentedParty(RepresentableParty.builder().id(0L).type(RepresentableParty.Type.CITIZEN).code("EE11223344556").build());
        UUID jwtId = UUID.randomUUID();
        SignedJWT signedJwt = jwtUtils.createSignedJwt(jwtId, userInfo);
        jwtTokenInfoService.createJwtTokenInfo(jwtId, "legacySessionId", new Timestamp(signedJwt.getJWTClaimsSet().getExpirationTime().getTime()));

        String serializedToken = signedJwt.serialize();

        assertNotNull(jwtUtils.getUserSession(serializedToken));
    }

    @Test
    void getUserSession_SignedButNotRegistered_ReturnsNull() {
        UserInfo userInfo = new UserInfo();
        userInfo.setRepresentedParty(RepresentableParty.builder().id(0L).type(RepresentableParty.Type.CITIZEN).code("EE11223344556").build());
        SignedJWT signedJwt = jwtUtils.createSignedJwt(UUID.randomUUID(), userInfo);

        String serializedToken = signedJwt.serialize();

        assertNull(jwtUtils.getUserSession(serializedToken));
    }

    @Test
    void getUserSession_SignedWithAnotherKey_ReturnsNull() throws Exception {
        SignedJWT jwt = getSignedJwtFromTestKeystore(new UserInfo());

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    @Test
    void getUserSession_MissingIssueTime_ReturnsNull() {
        Date issueTime = null;
        Date expirationTime = nowPlusSeconds(120);
        SignedJWT jwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), null, null, issueTime, expirationTime);

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    @Test
    void getUserSession_MissingExpirationTime_ReturnsNull() {
        Date issueTime = nowPlusSeconds(0);
        Date expirationTime = null;
        SignedJWT jwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), null, null, issueTime, expirationTime);

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    @Test
    void getUserSession_IssueTimeInTheFuture_ReturnsNull() {
        Date issueTime = nowPlusSeconds(60);
        Date expirationTime = nowPlusSeconds(120);
        SignedJWT jwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), null, null, issueTime, expirationTime);

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    @Test
    void getUserSession_MissingNotBeforeTime_ReturnsNull() {
        Date issueTime = nowPlusSeconds(0);
        Date notBeforeTime = null;
        Date expirationTime = nowPlusSeconds(120);

        SignedJWT jwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), null, Collections.singletonMap(NOT_BEFORE, notBeforeTime), issueTime, expirationTime);

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    @Test
    void getUserSession_NotBeforeTimeInTheFuture_ReturnsNull() {
        Date issueTime = nowPlusSeconds(0);
        Date notBeforeTime = nowPlusSeconds(60);
        Date expirationTime = nowPlusSeconds(120);

        SignedJWT jwt = jwtUtils.getSignedJWTWithClaims(UUID.randomUUID(), null, Map.of(NOT_BEFORE, notBeforeTime), issueTime, expirationTime);

        assertNull(jwtUtils.getUserSession(jwt.serialize()));
    }

    private SignedJWT getSignedJwtFromTestKeystore(UserInfo userInfo) throws Exception {
        Date issueDate = userInfo.getLoggedInDate() == null
                ? new Date()
                : userInfo.getLoggedInDate();
        Date expirationDate = userInfo.getLoginExpireDate() == null
                ? DateUtils.addMinutes(issueDate, legacyPortalIntegrationConfig.getSessionTimeoutMinutes())
                : userInfo.getLoginExpireDate();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.PS256),
                new JWTClaimsSet.Builder()
                        .jwtID(UUID.randomUUID().toString())
                        .issuer(jwtSignatureConfig.getIssuer())
                        .issueTime(issueDate)
                        .expirationTime(expirationDate)
                        .subject(userInfo.getPersonalCode())
                        .claim("personalCode", userInfo.getPersonalCode())
                        .claim("firstName", userInfo.getFirstName())
                        .claim("lastName", userInfo.getLastName())
                        .build()
        );

        signedJWT.sign(getTestJwtSigner());

        return signedJWT;
    }

    private JWSSigner getTestJwtSigner() throws Exception {

        InputStream inputStream = Files.newInputStream(Paths.get("src", "test", "resources", "test_jwtkeystore.jks"));

        return new RSASSASigner(JwtUtils.getJwtSignKeyFromKeystore("JKS", inputStream, "changeit".toCharArray(), "jwtsign"));
    }

    private Date nowPlusSeconds(int seconds) {
        return Date.from(Instant.now().plusSeconds(seconds));
    }
}
