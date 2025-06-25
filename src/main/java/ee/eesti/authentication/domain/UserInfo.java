package ee.eesti.authentication.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;

/**
 * Models the user info.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfo implements Serializable {

    private static final String ESTONIAN_PERSONAL_CODE_PREFIX = "EE";

    private String personalCode;
    private String authenticatedAs;
    private String hash;
    private String firstName;
    private String lastName;
    private Date loggedInDate;
    private Date loginExpireDate;
    private String authMethod;
    private String acr;
    private RepresentableParty representedParty;

    private String govssoSessionId;
    private String authorizedParty;

    public String getFullName() {
        return firstName + " " + lastName;
    }

    public String getPersonalCodeWithoutCountryPrefix() {
        if (personalCode == null) {
            return null;
        }

        return personalCode.trim().matches("^[a-zA-Z]{2}\\d{11}$")
                ? personalCode.trim().substring(2)
                : personalCode;
    }

    public String getCountryPrefix(){
        if (personalCode == null) {
            return null;
        }

        String countryPrefix = personalCode.substring(0, 2);

        return countryPrefix.matches("^[a-zA-Z]{2}$")
                ? countryPrefix
                : null;
    }

    public boolean isHasEstonianPersonalCode() {
        return ESTONIAN_PERSONAL_CODE_PREFIX.equalsIgnoreCase(getCountryPrefix());
    }

}
