package ee.eesti.authentication.domain;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserInfoTest {


    @Test
    void getPersonalCodeWithoutCountryPrefix() {
        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  EE12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  lV12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("  Ru12345678901   ");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("12345678901"));

        userInfo.setPersonalCode("09876543210");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("09876543210"));

        userInfo.setPersonalCode("someInvalidString");
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is("someInvalidString"));

        userInfo.setPersonalCode(null);
        assertThat(userInfo.getPersonalCodeWithoutCountryPrefix(), is(nullValue()));
    }


    @Test
    void getCountryPrefix() {

        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertThat(userInfo.getCountryPrefix(), is("EE"));

        userInfo.setPersonalCode("LT12345678901");
        assertThat(userInfo.getCountryPrefix(), is("LT"));

        userInfo.setPersonalCode(null);
        assertNull(userInfo.getCountryPrefix());

        // according to https://e-gov.github.io/TARA-Doku/TehnilineKirjeldus#431-identsust%C3%B5end
        // personalCode contains ISO 3166-1 alpha-2 country code
        userInfo.setPersonalCode("11123123123");
        assertNull(userInfo.getCountryPrefix());

    }

    @Test
    void isHasEstonianPersonalCode() {
        UserInfo userInfo = new UserInfo();

        userInfo.setPersonalCode("EE12345678901");
        assertTrue(userInfo.isHasEstonianPersonalCode());

        userInfo.setPersonalCode("LT12345678901");
        assertFalse(userInfo.isHasEstonianPersonalCode());

        userInfo.setPersonalCode(null);
        assertFalse(userInfo.isHasEstonianPersonalCode());

    }
}
