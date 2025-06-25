package ee.eesti.authentication.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.UUID;

@Data
@AllArgsConstructor
public class ExceptionResponse {
    private UUID uuid;
}
