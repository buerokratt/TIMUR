package ee.eesti.authentication.domain;

import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
public class SelectRepresentablePartyRequest {
    @NotNull
    private Long id;
}
