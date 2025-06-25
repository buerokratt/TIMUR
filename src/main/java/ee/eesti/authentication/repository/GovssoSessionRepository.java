package ee.eesti.authentication.repository;

import ee.eesti.authentication.repository.entity.GovssoSessionEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GovssoSessionRepository extends CrudRepository<GovssoSessionEntity, String> {}
