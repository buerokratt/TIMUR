package ee.eesti.authentication.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import ee.eesti.AbstractSpringBasedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

class DateToTimestampConverterTest extends AbstractSpringBasedTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void serialize_DateFieldsAreSerializedToNumber() throws Exception {
        TestDataStructure userInfo = new TestDataStructure(new Date(42L));
        String serializedJson = objectMapper.writeValueAsString(userInfo);

        JsonNode jsonNode = objectMapper.readTree(serializedJson);
        assertThat(jsonNode, is(notNullValue()));
        assertThat(jsonNode.get("dateField").asLong(), is(42L));
    }

    private record TestDataStructure(
            @JsonSerialize(using = DateToTimestampConverter.class) Date dateField
    ) {}

}
