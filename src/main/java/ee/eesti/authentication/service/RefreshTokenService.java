package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.AppRefreshTokenConfig;
import ee.eesti.authentication.repository.RefreshTokenRepository;
import ee.eesti.authentication.repository.entity.AppRefreshTokenEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Base64;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.DAYS;
import static org.springframework.boot.web.server.Cookie.SameSite.STRICT;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AppRefreshTokenConfig appRefreshTokenConfig;

    private final StringKeyGenerator refreshTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    public AppRefreshTokenEntity findByToken(String token) {
        return refreshTokenRepository.findByValue(token).orElse(null);
    }

    public String create(String sessionId) {
        Instant issuedAt = now();
        Instant expiresAt = issuedAt.plus(appRefreshTokenConfig.getTtlInDays(), DAYS);
        AppRefreshTokenEntity entity = new AppRefreshTokenEntity()
                .setIssuedAt(issuedAt)
                .setExpiresAt(expiresAt)
                .setLegacySessionId(sessionId)
                .setValue(this.refreshTokenGenerator.generateKey());
        return refreshTokenRepository.save(entity).getValue();
    }

    public void invalidateByLegacySessionId(String sessionId) {
        refreshTokenRepository.saveAll(
                refreshTokenRepository.findByLegacySessionIdAndInvalidatedFalse(sessionId).stream()
                        .map(this::invalidate)
                        .toList());
    }

    public void invalidateByToken(String tokenValue) {
        refreshTokenRepository.findByValueAndInvalidatedFalse(tokenValue).ifPresent((this::invalidate));
    }

    private AppRefreshTokenEntity invalidate(AppRefreshTokenEntity appRefreshTokenEntity) {
        appRefreshTokenEntity.setInvalidatedAt(now());
        appRefreshTokenEntity.setInvalidated(true);
        return appRefreshTokenEntity;
    }

    public String getResponseCookie(String token) {
        return ResponseCookie.from(appRefreshTokenConfig.getCookieName(),token)
                .secure(true)
                .httpOnly(true)
                .sameSite(STRICT.toString())
                .path("/timur")
                .build()
                .toString();
    }


}
