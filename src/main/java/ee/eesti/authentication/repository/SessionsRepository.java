package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.SessionsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface SessionsRepository extends JpaRepository<SessionsEntity, Long> {

  Optional<SessionsEntity> findBySessionId(String sessionId);

  List<SessionsEntity> findAllBySessionIdInAndValidToAfter(Collection<String> sessionsId, LocalDateTime validTo);


  List<SessionsEntity> findAllByValidToAfterAndAuthenticatedAs(LocalDateTime validTo, String authenticatedAs);

}
