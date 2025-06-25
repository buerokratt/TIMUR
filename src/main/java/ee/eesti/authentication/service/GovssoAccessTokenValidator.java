package ee.eesti.authentication.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Based on {@link org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator}
 */
@RequiredArgsConstructor
public class GovssoAccessTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);
    private static final String CLIENT_ID_CLAIM = "client_id";

    private final ClientRegistration clientRegistration;
    private final String audience;

    private final Duration clockSkew = DEFAULT_CLOCK_SKEW;
    private final Clock clock = Clock.systemUTC();

    @Override
    public OAuth2TokenValidatorResult validate(Jwt accessToken) {
        // Identical to OidcIdTokenValidator
        Map<String, Object> invalidClaims = validateRequiredClaims(accessToken);
        if (!invalidClaims.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(invalidAccessToken(invalidClaims));
        }

        // Specific to Timur/GovSSO
        // Access Token client_id väärtus peab vastama eesti.ee klientrakenduse ID-le (sama, mis ID Tokenis aud väärtus
        // ja autentimispäringus client_id väärtus).
        String clientId = accessToken.getClaimAsString(CLIENT_ID_CLAIM);
        if (!clientId.equals(this.clientRegistration.getClientId())) {
            invalidClaims.put(CLIENT_ID_CLAIM, clientId);
        }

        // Specific to Timur/GovSSO
        // Access Token aud väärtused peavad vastama autentimispäringus määratud audience väärtustele.
        List<String> accessTokenAudience = accessToken.getAudience();
        String[] audienceArray = audience.split("[\\s]+");
        for (String audienceUrl : audienceArray) {
            audienceUrl = audienceUrl.replace("www.", "");
            if (accessTokenAudience.stream().noneMatch(audienceUrl::startsWith)) {
                invalidClaims.put(IdTokenClaimNames.AUD, accessTokenAudience);
                break;
            }
        }

        // Identical to OidcIdTokenValidator
        Instant now = Instant.now(this.clock);
        if (now.minus(this.clockSkew).isAfter(accessToken.getExpiresAt())) {
            invalidClaims.put(IdTokenClaimNames.EXP, accessToken.getExpiresAt());
        }

        // Identical to OidcIdTokenValidator
        if (now.plus(this.clockSkew).isBefore(accessToken.getIssuedAt())) {
            invalidClaims.put(IdTokenClaimNames.IAT, accessToken.getIssuedAt());
        }

        // Specific to Timur/GovSSO
        // Access Token kehtivusaeg (vahemikus 1-15 minutit)
        if (now.minus(this.clockSkew).plusSeconds(60).isAfter(accessToken.getExpiresAt()) ||
                now.plus(this.clockSkew).plusSeconds(15 * 60).isBefore(accessToken.getExpiresAt())) {
            invalidClaims.put(IdTokenClaimNames.EXP, accessToken.getExpiresAt());
        }

        if (!invalidClaims.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(invalidAccessToken(invalidClaims));
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2Error invalidAccessToken(Map<String, Object> invalidClaims) {
        return new OAuth2Error(
                "invalid_access_token",
                "The access token contains invalid claims: " + invalidClaims,
                null);
    }

    private static Map<String, Object> validateRequiredClaims(Jwt accessToken) {
        Map<String, Object> requiredClaims = new HashMap<>();
        URL issuer = accessToken.getIssuer();
        if (issuer == null) {
            requiredClaims.put(IdTokenClaimNames.ISS, issuer);
        }
        String subject = accessToken.getSubject();
        if (subject == null) {
            requiredClaims.put(IdTokenClaimNames.SUB, subject);
        }
        List<String> audience = accessToken.getAudience();
        if (CollectionUtils.isEmpty(audience)) {
            requiredClaims.put(IdTokenClaimNames.AUD, audience);
        }
        Instant expiresAt = accessToken.getExpiresAt();
        if (expiresAt == null) {
            requiredClaims.put(IdTokenClaimNames.EXP, expiresAt);
        }
        Instant issuedAt = accessToken.getIssuedAt();
        if (issuedAt == null) {
            requiredClaims.put(IdTokenClaimNames.IAT, issuedAt);
        }
        return requiredClaims;
    }
}
