package ee.eesti.authentication.domain;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class SelectRepresentablePartyByCodeRequest {
    @NotBlank
    private String code;
}
