package ee.eesti.authentication.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import java.time.Instant;
import java.util.Date;

import static java.util.Objects.requireNonNull;

@Value
@Builder
public class UserInfoResponseDto {

    String personalCode;
    String authenticatedAs;
    String hash;
    String firstName;
    String lastName;
    @JsonSerialize(using = DateToTimestampConverter.class)
    @Schema(implementation = Long.class)
    Date loggedInDate;
    @JsonSerialize(using = DateToTimestampConverter.class)
    @Schema(implementation = Long.class)
    Date loginExpireDate;
    String authMethod;
    String acr;
    RepresentableParty representedParty;
    @JsonProperty("govsso")
    Govsso govsso;
    Long currentTimestamp;

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public static UserInfoResponseDto from(UserSession userSession) {
        UserInfo userInfo = userSession.userInfo();
        GovssoSession govssoSession = userSession.govssoSession();
        return UserInfoResponseDto.builder()
                .personalCode(userInfo.getPersonalCode())
                .authenticatedAs(userInfo.getAuthenticatedAs())
                .hash(userInfo.getHash())
                .firstName(userInfo.getFirstName())
                .lastName(userInfo.getLastName())
                .loggedInDate(userInfo.getLoggedInDate())
                .loginExpireDate(userInfo.getLoginExpireDate())
                .authMethod(userInfo.getAuthMethod())
                .acr(userInfo.getAcr())
                .representedParty(userInfo.getRepresentedParty())
                .govsso(govssoSession != null
                        ? Govsso.from(govssoSession.idToken(), govssoSession.accessToken())
                        : null)
                .currentTimestamp(Instant.now().getEpochSecond())
                .build();
    }

    public record Govsso(String sessionId, String token, Long expiration) {

        public static Govsso from(@NonNull OidcIdToken govssoIdToken, OAuth2AccessToken oAuth2AccessToken) {
            return new Govsso(
                    requireNonNull(govssoIdToken.getClaimAsString("sid")),
                    requireNonNull(oAuth2AccessToken.getTokenValue()),
                    requireNonNull(govssoIdToken.getExpiresAt()).getEpochSecond());
        }

    }

}
