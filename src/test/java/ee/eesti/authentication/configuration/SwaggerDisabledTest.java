package ee.eesti.authentication.configuration;

import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = "springdoc.api-docs.enabled=false")
class SwaggerDisabledTest extends AbstractSpringBasedTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void swaggerUi_IndexIsNotAccessible() throws Exception {
        mvc.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isNotFound());
    }

}
