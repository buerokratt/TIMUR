package ee.eesti.authentication.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Based on {@link org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator}
 */
@RequiredArgsConstructor
public final class GovssoLogoutTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);
    private static final String EVENTS_CLAIM = "events";
    private static final String SESSION_ID_CLAIM = "sid";
    private static final String BACK_CHANNEL_LOGOUT_MEMBER_NAME = "http://schemas.openid.net/event/backchannel-logout";

    private final ClientRegistration clientRegistration;
    private final Clock clock = Clock.systemUTC();

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        // 2.6. Logout Token Validation
        // https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.6
        Set<String> invalidClaims = new HashSet<>();
        // > 4. Validate the `iss`, `aud`, and `iat` Claims in the same way they are validated in ID Tokens."
        // We will skip validating `iss` as expected value is not set.
        // TODO AUT-1059: Set `iss` value in configuration and start validating it.
        invalidClaims.addAll(validateAudience(token));
        invalidClaims.addAll(validateIssuedAtTime(token));
        // > 5. Verify that the Logout Token contains a `sub` Claim, a `sid` Claim, or both.
        // > GovSSO only uses `sid` claim.
        invalidClaims.addAll(validateSessionId(token));
        // 6. Verify that the Logout Token contains an `events` Claim whose value is JSON object containing
        //    the member name http://schemas.openid.net/event/backchannel-logout.
        invalidClaims.addAll(validateEvents(token));
        if (!invalidClaims.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(invalidLogoutToken(token, invalidClaims));
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2Error invalidLogoutToken(Jwt token, Set<String> invalidClaims) {
        Map<String, Object> invalidClaimsMap = invalidClaims.stream()
                .collect(Collectors.toMap(Function.identity(), token::getClaim));
        return new OAuth2Error("invalid_id_token", "The ID Token contains invalid claims: " + invalidClaimsMap,
                "https://openid.net/specs/openid-connect-backchannel-1_0.html#rfc.section.2.6");
    }

    private Set<String> validateAudience(Jwt token) {
        if (!token.getAudience().contains(this.clientRegistration.getClientId())) {
            return Set.of(IdTokenClaimNames.AUD);
        }
        return Set.of();
    }

    private Set<String> validateIssuedAtTime(Jwt token) {
        Instant issuedAt = token.getIssuedAt();
        Instant now = Instant.now(this.clock);
        if (issuedAt == null || now.plus(CLOCK_SKEW).isBefore(issuedAt)) {
            return Set.of(IdTokenClaimNames.IAT);
        }
        return Set.of();
    }

    private Set<String> validateSessionId(Jwt token) {
        if (token.getClaim(SESSION_ID_CLAIM) == null) {
            return Set.of(SESSION_ID_CLAIM);
        }
        return Set.of();
    }

    private Set<String> validateEvents(Jwt token) {
        Map<String, Object> events = token.getClaimAsMap(EVENTS_CLAIM);
        if (events == null || !events.containsKey(BACK_CHANNEL_LOGOUT_MEMBER_NAME)) {
            return Set.of(EVENTS_CLAIM);
        }
        return Set.of();
    }

}
