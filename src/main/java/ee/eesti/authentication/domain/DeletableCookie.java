package ee.eesti.authentication.domain;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class DeletableCookie {

    @NotBlank
    private String name;

    private String domain;

    @NotBlank
    private String path;

}
