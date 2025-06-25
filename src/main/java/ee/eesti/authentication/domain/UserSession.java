package ee.eesti.authentication.domain;

import lombok.NonNull;

public record UserSession(
        @NonNull UserInfo userInfo,
        GovssoSession govssoSession
) {
}
