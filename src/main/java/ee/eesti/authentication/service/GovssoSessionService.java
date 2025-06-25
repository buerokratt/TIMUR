package ee.eesti.authentication.service;

import ee.eesti.authentication.domain.GovssoSession;
import ee.eesti.authentication.repository.GovssoSessionRepository;
import ee.eesti.authentication.repository.entity.GovssoSessionEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.SerializationUtils;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class GovssoSessionService {

    private final GovssoSessionRepository repository;

    public void save(GovssoSession session) {
        repository.save(toEntity(session));
        log.debug("Saved GovSSO session with ID Token sid={}", session.sessionId());
    }

    public Optional<GovssoSession> findById(String sessionId) {
        return findByIdIncludingExpired(sessionId)
                .filter(session -> {
                    Instant expiresAt = Objects.requireNonNull(session.idToken().getExpiresAt());
                    boolean notExpired = Instant.now().isBefore(expiresAt);
                    if (!notExpired) {
                        log.debug("GovSSO session with ID Token sid={} expired", session.sessionId());
                    }
                    return notExpired;
                });
    }

    public Optional<GovssoSession> findByIdIncludingExpired(String sessionId) {
        return repository.findById(sessionId)
                .map(this::toDomain);
    }

    public void remove(String sessionId) {
        repository.deleteById(sessionId);
        log.info("Deleted GovSSO ID Token with sid={}", sessionId);
    }

    private GovssoSessionEntity toEntity(GovssoSession session) {
        return new GovssoSessionEntity(
                session.sessionId(),
                SerializationUtils.serialize(session.idToken()),
                SerializationUtils.serialize(session.refreshToken()),
                SerializationUtils.serialize(session.accessToken()));
    }

    private GovssoSession toDomain(GovssoSessionEntity entity) {
        return new GovssoSession(
                SerializationUtils.deserialize(entity.getIdToken()),
                SerializationUtils.deserialize(entity.getRefreshToken()),
                SerializationUtils.deserialize(entity.getAccessToken()));
    }

}
