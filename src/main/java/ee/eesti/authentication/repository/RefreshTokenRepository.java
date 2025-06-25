package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.AppRefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<AppRefreshTokenEntity, Long> {
    Optional<AppRefreshTokenEntity> findByValue(String token);
    List<AppRefreshTokenEntity> findByLegacySessionIdAndInvalidatedFalse(String legacySessionId);
    Optional<AppRefreshTokenEntity> findByValueAndInvalidatedFalse(String token);
}
