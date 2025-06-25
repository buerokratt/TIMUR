package ee.eesti.authentication.configuration.govsso;

import ee.eesti.authentication.constant.EidasLevelOfAssurance;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import static ee.eesti.authentication.constant.EidasLevelOfAssurance.SUBSTANTIAL;

public class GovssoLevelOfAssuranceValidator implements OAuth2TokenValidator<Jwt> {

    private static final String LEVEL_OF_ASSURANCE_CLAIM = "acr";

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String levelOfAssuranceString = token.getClaimAsString(LEVEL_OF_ASSURANCE_CLAIM);
        if (levelOfAssuranceString == null) {
            return invalidAcrValue();
        }
        EidasLevelOfAssurance levelOfAssurance;
        try {
            levelOfAssurance = EidasLevelOfAssurance.fromValue(levelOfAssuranceString);
        } catch (IllegalArgumentException e) {
            return invalidAcrValue();
        }
        if (!levelOfAssurance.isAtLeast(SUBSTANTIAL)) {
            return insufficientAcrValue();
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidatorResult insufficientAcrValue() {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(
                        "invalid_token",
                        "The ID Token contains insufficient `acr` (eIDAS level of assurance) value, " +
                                "expected at least \"" + SUBSTANTIAL.getValue() + "\"",
                        null
                )
        );
    }

    private static OAuth2TokenValidatorResult invalidAcrValue() {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(
                        "invalid_token",
                        "The ID Token contains invalid `acr` (eIDAS level of assurance) value",
                        "https://e-gov.github.io/GOVSSO/TechnicalSpecification#71-verification-of-the-id-token-and-logout-token"
                )
        );
    }

}
