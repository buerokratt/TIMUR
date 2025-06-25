package ee.eesti.authentication.constant;

public enum EidasLevelOfAssurance implements Comparable<EidasLevelOfAssurance> {

    LOW,
    SUBSTANTIAL,
    HIGH;

    public static EidasLevelOfAssurance fromValue(String value) {
        return EidasLevelOfAssurance.valueOf(value.toUpperCase());
    }

    public String getValue() {
        return name().toLowerCase();
    }

    public boolean isAtLeast(EidasLevelOfAssurance minimumLevel) {
        return this.compareTo(minimumLevel) >= 0;
    }

}
