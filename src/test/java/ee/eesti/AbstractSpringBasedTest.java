package ee.eesti;


import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

@ActiveProfiles(profiles = {"mock"})
@SpringBootTest
@AutoConfigureMockMvc
public abstract class AbstractSpringBasedTest {

    private static final String DOCKER_POSTGRESQL_CONTAINER_NAME = "postgres:14";
    private static final String REDIS_CONTAINER_NAME = "redis:6.2.14-alpine";

    static {
        @SuppressWarnings("resource")
		var postgreSQLContainer = new PostgreSQLContainer(DOCKER_POSTGRESQL_CONTAINER_NAME)
                .withDatabaseName("timur")
                .withUsername("timur")
                .withPassword("timur");
        postgreSQLContainer.start();
        System.setProperty("spring.datasource.url", postgreSQLContainer.getJdbcUrl());
    }

    static {
        @SuppressWarnings("resource")
		GenericContainer<?> redis =
                new GenericContainer<>(DockerImageName.parse(REDIS_CONTAINER_NAME)).withExposedPorts(6379);
        redis.start();
        System.setProperty("spring.data.redis.host", redis.getHost());
        System.setProperty("spring.data.redis.port", redis.getMappedPort(6379)
                .toString());
    }

}
