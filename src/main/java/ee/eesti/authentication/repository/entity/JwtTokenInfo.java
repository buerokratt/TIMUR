package ee.eesti.authentication.repository.entity;


import lombok.Data;
import lombok.EqualsAndHashCode;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.sql.Timestamp;
import java.util.UUID;

/**
 * Entity that contains info about jwt.
 * Entity is associated with "jwt_token" table.
 */
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "jwt_token")
@Data
public class JwtTokenInfo extends GenericJwtTokenInfo {

    @Column(name = "session_id", length = 36, nullable = false)
    private String legacySessionId;

    public JwtTokenInfo() {
    }

    public JwtTokenInfo(UUID jwtUuid, Timestamp expiredDate, Timestamp issuedDate, boolean blacklisted, Timestamp blacklistedDate, String legacySessionId) {
        super(jwtUuid, expiredDate, issuedDate, blacklisted, blacklistedDate);
        this.legacySessionId = legacySessionId;
    }

}
