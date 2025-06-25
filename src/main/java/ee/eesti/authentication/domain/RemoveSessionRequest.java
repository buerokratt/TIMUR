package ee.eesti.authentication.domain;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class RemoveSessionRequest {
    @NotBlank
    private String sessionId;
}
