package ee.eesti.authentication.configuration;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.JwtSignatureConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static com.nimbusds.jwt.JWTClaimNames.EXPIRATION_TIME;
import static com.nimbusds.jwt.JWTClaimNames.ISSUED_AT;
import static com.nimbusds.jwt.JWTClaimNames.JWT_ID;
import static com.nimbusds.jwt.JWTClaimNames.NOT_BEFORE;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class SecurityConfiguration {

    @Value("${cors.allowed-origins:*}")
    private List<String> allowedOrigins;
    private final JwtSignatureConfig jwtSignatureConfig;

    @Bean
    public JWSSigner rsassaSigner() {
        try {
            return new RSASSASigner(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));

        } catch (Exception e) {
            log.error("Unable to initialize RSASSASigner ", e);
            throw new IllegalArgumentException("RSASSASigner not initialized, check configuration properties with prefix jwt-integration.signature");
        }
    }

    @Bean
    public JWSVerifier jwsVerifier() {

        try {
            return new RSASSAVerifier(
                    JwtUtils.getJwtSignKeyFromKeystore(
                            jwtSignatureConfig.getKeyStoreType(),
                            jwtSignatureConfig.getKeyStore().getInputStream(),
                            jwtSignatureConfig.getKeyStorePassword().toCharArray(),
                            jwtSignatureConfig.getKeyAlias()));
        } catch (Exception e) {
            log.error("Unable to initialize RSSASSAVerifier", e);
            throw new IllegalArgumentException(e);
        }
    }

    @Bean
    public JWTClaimsSetVerifier<SecurityContext> claimsVerifier() {
        JWTClaimsSet exactMatchClaims = new JWTClaimsSet.Builder()
                .issuer(jwtSignatureConfig.getIssuer())
                .build();
        Set<String> requiredClaims = Set.of(EXPIRATION_TIME, ISSUED_AT, JWT_ID, NOT_BEFORE);

        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
                new DefaultJWTClaimsVerifier<>(exactMatchClaims, requiredClaims);
        claimsVerifier.setMaxClockSkew(0);

        return claimsVerifier;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(allowedOrigins);
        configuration.setAllowedMethods(Stream.of(HttpMethod.GET, HttpMethod.POST).map(HttpMethod::name).toList());
        configuration.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
