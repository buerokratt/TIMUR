package ee.eesti.authentication.configuration.refreshtoken;

import ee.eesti.authentication.constant.AppRefreshTokenConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

@Component
@Slf4j
public class RefreshTokenEncryptionUtil {
    private final Key key;

    public RefreshTokenEncryptionUtil(AppRefreshTokenConfig appRefreshTokenConfig) {
        this.key = new SecretKeySpec(appRefreshTokenConfig.getEncryptionKey().getBytes(UTF_8), "AES");
    }

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";

    public String encrypt(String tokenValue) {
        try {
            Cipher c = Cipher.getInstance(ALGORITHM);
            c.init(Cipher.ENCRYPT_MODE, key);
            return getEncoder().encodeToString(c.doFinal(tokenValue.getBytes()));
        } catch (Exception e) {
            log.error("Token encryption failed");
            throw new RuntimeException(e);
        }
    }

    public String decrypt(String dbData) {
        try {
            Cipher c = Cipher.getInstance(ALGORITHM);
            c.init(Cipher.DECRYPT_MODE, key);
            return new String(c.doFinal(getDecoder().decode((dbData))));
        } catch (Exception e) {
            log.error("Token decryption failed");
            throw new RuntimeException(e);
        }
    }
}
