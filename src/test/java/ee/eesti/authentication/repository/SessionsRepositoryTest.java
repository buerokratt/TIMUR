package ee.eesti.authentication.repository;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

class SessionsRepositoryTest extends AbstractSpringBasedTest {


    @Autowired
    private SessionsRepository sessionsRepository;

    @BeforeEach
    void setUp() {
        sessionsRepository.deleteAll();
    }

    @Test
    void findAllBySessionIdInAndValidToAfter() {

        LocalDateTime testDate = LocalDateTime.now().minusMinutes(1L);
        List<String> sessionsId = Arrays.asList("test", "test2");
        sessionsId.forEach(
                sessionId -> {
                    SessionsEntity entity1 = new SessionsEntity();
                    entity1.setSessionId(sessionId);
                    entity1.setValidTo(LocalDateTime.now());
                    sessionsRepository.saveAndFlush(entity1);
                }
        );

        List<SessionsEntity> allBySessionIdAndValidToAfter = sessionsRepository.findAllBySessionIdInAndValidToAfter(sessionsId, testDate);

        assertThat(allBySessionIdAndValidToAfter, hasSize(2));
    }
}