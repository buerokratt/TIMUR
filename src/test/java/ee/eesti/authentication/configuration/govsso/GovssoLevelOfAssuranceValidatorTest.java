package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.constant.EidasLevelOfAssurance;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GovssoLevelOfAssuranceValidatorTest {

    private final GovssoLevelOfAssuranceValidator validator = new GovssoLevelOfAssuranceValidator();

    @Test
    void validate_acrMissing_validationFails() {
        Jwt token = createTokenWithAcrValue(null);
        OAuth2TokenValidatorResult validatorResult = validator.validate(token);
        assertFailure(validatorResult);
    }

    @Test
    void validate_acrUnknownValue_validationFails() {
        Jwt token = createTokenWithAcrValue("super-duper-high");
        OAuth2TokenValidatorResult validatorResult = validator.validate(token);
        assertFailure(validatorResult);
    }

    @Test
    void validate_acrLowerThanRequired_validationFails() {
        Jwt token = createTokenWithAcrValue(EidasLevelOfAssurance.LOW.getValue());
        OAuth2TokenValidatorResult validatorResult = validator.validate(token);
        assertFailure(validatorResult);
    }

    @Test
    void validate_acrEqualToRequired_validationSuccess() {
        Jwt token = createTokenWithAcrValue(EidasLevelOfAssurance.SUBSTANTIAL.getValue());
        OAuth2TokenValidatorResult validatorResult = validator.validate(token);
        assertSuccess(validatorResult);
    }

    @Test
    void validate_acrHigherThanRequired_validationSuccess() {
        Jwt token = createTokenWithAcrValue(EidasLevelOfAssurance.HIGH.getValue());
        OAuth2TokenValidatorResult validatorResult = validator.validate(token);
        assertSuccess(validatorResult);
    }

    private void assertSuccess(OAuth2TokenValidatorResult validatorResult) {
        assertFalse(validatorResult.hasErrors());
    }

    private void assertFailure(OAuth2TokenValidatorResult validatorResult) {
        assertTrue(validatorResult.hasErrors());
    }

    private Jwt createTokenWithAcrValue(String acrValue) {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("claims", "cannot be empty");
        if (acrValue != null) {
            claims.put("acr", acrValue);
        }
        return new Jwt("ignored", Instant.now(), Instant.now().plusSeconds(60), Map.of("headers", "cannot be empty"), claims);
    }
}
