package ee.eesti.authentication.configuration.refreshtoken;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class RefreshTokenEncrypt implements AttributeConverter<String,String> {

    RefreshTokenEncryptionUtil encryptionUtil;

    public RefreshTokenEncrypt(RefreshTokenEncryptionUtil encryptionUtil) {
        this.encryptionUtil = encryptionUtil;
    }

    @Override
    public String convertToDatabaseColumn(String s) {
        return encryptionUtil.encrypt(s);
    }

    @Override
    public String convertToEntityAttribute(String s) {
        return encryptionUtil.decrypt(s);
    }
}