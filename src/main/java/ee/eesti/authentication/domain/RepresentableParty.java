package ee.eesti.authentication.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.jackson.Jacksonized;

import java.io.Serializable;

@Data
@Builder
@Jacksonized
public class RepresentableParty implements Serializable {
    @Schema(description = """
            * CITIZEN - 0
            * BUSINESS - institution id
            """)
    private Long id;

    @JsonSerialize
    private Type type;

    @Schema(description = """
            * CITIZEN - citizen personal code
            * BUSINESS - institution registry code
            """)
    private String code;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = """
            * CITIZEN - citizen full name
            * BUSINESS - institution name
            """)
    private String name;

    @Getter
    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public enum Type {
        CITIZEN(0),
        BUSINESS(1),
        UNKNOWN(Integer.MAX_VALUE);

        private final int sortOrder;
    }
}
