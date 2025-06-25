package ee.eesti.authentication.repository.entity;

import lombok.Value;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Value
@RedisHash
public class GovssoSessionEntity {

    @Id
    String sessionId;
    byte[] idToken;
    byte[] refreshToken;
    byte[] accessToken;
}
