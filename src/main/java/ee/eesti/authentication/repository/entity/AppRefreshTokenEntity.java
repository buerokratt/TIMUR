package ee.eesti.authentication.repository.entity;

import ee.eesti.authentication.configuration.refreshtoken.RefreshTokenEncrypt;
import lombok.*;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import static java.time.Instant.now;



@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_token")
public class AppRefreshTokenEntity {
    @Id
    @Column(name = "refresh_token_uuid", nullable = false)
    private UUID refreshTokenUUID = UUID.randomUUID();

    @Column(nullable = false, unique = true)
    @Convert(converter = RefreshTokenEncrypt.class)
    private String value;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Instant issuedAt = now();

    @Column
    private boolean invalidated;

    @Column
    private Instant invalidatedAt;

    @Column(name = "session_id", length = 36, nullable = false)
    private String legacySessionId;

    public boolean isExpired() {
        return expiresAt.isBefore(now());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(refreshTokenUUID);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AppRefreshTokenEntity other = (AppRefreshTokenEntity) obj;
        return Objects.equals(refreshTokenUUID, other.getRefreshTokenUUID());
    }
}
