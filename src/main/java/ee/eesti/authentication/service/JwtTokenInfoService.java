package ee.eesti.authentication.service;

import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.govsso.GovssoAuthenticationSuccessHandler;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import ee.eesti.authentication.aop.Timed;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * For managing JwtTokens
 */
@Service
@Slf4j
@Timed
@RequiredArgsConstructor
public class JwtTokenInfoService {

	private final LegacyPortalIntegrationConfig legacyPortalIntegrationConfig;
	private final SessionsService sessionsService;
	private final JwtUtils jwtUtils;

	private final JwtTokenInfoRepository jwtTokenInfoRepository;
	private final SessionsRepository sessionsRepository;


	/**
	 *
	 * @param jwtTokenUuid UUID of jwtToken
	 * @param legacySessionId session ID
	 * @param expiredDate expired date for token
	 * @return contains info about jwtToken
	 */
	public JwtTokenInfo createJwtTokenInfo(UUID jwtTokenUuid, String legacySessionId, Timestamp expiredDate) {
		try {
			JwtTokenInfo jwtTokenInfo = new JwtTokenInfo();
			jwtTokenInfo.setLegacySessionId(legacySessionId);
			jwtTokenInfo.setExpiredDate(expiredDate);
			jwtTokenInfo.setJwtUuid(jwtTokenUuid);

			return jwtTokenInfoRepository.saveAndFlush(jwtTokenInfo);

		} catch (Exception e) {
			log.error("Exception on creating JwtTokenInfo", e);
			throw new IllegalStateException(e);
		}
	}


	public String extendSessionObtainedFromJwt(String oldJwtId, UserInfo userInfoFromJwt, HttpServletRequest request, HttpServletResponse response) {

		userInfoFromJwt.setLoginExpireDate(DateUtils.addMinutes(new Date(), legacyPortalIntegrationConfig.getSessionTimeoutMinutes()));

		UUID jwtTokenId = UUID.randomUUID();
		SignedJWT signedJwt = jwtUtils.createSignedJwt(jwtTokenId, userInfoFromJwt);


		JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
				.findById(UUID.fromString(oldJwtId))
				.orElse(null);

		String legacySessionId = GovssoAuthenticationSuccessHandler.DEFAULT_LEGACY_SESSION_ID_VALUE;

		if (userInfoFromJwt.isHasEstonianPersonalCode()) {
			SessionsEntity sessionEntityToExtend = null;
			if (jwtTokenInfo != null && jwtTokenInfo.getLegacySessionId() != null) {
				sessionEntityToExtend = sessionsRepository.findBySessionId(jwtTokenInfo.getLegacySessionId())
						.orElse(null);
			}

			if (sessionEntityToExtend != null) {
				sessionEntityToExtend.setLastModified(LocalDateTime.now());
				sessionEntityToExtend.setValidTo(LocalDateTime.ofInstant(Instant.ofEpochMilli(userInfoFromJwt.getLoginExpireDate()
						.getTime()), ZoneId.systemDefault()));

				sessionsRepository.saveAndFlush(sessionEntityToExtend);

			} else {
				// existing sessionsEntity is not found
				// create unauthenticated session to legacy portal
				sessionEntityToExtend = sessionsService.openLegacyPortalLoginSession(request, userInfoFromJwt, ChannelType.AUTENTIMATA, null);
			}


			legacySessionId = sessionEntityToExtend.getSessionId();
		}

		createJwtTokenInfo(
				jwtTokenId,
				legacySessionId,
				new Timestamp(userInfoFromJwt.getLoginExpireDate()
						.getTime()));

		// Delete JWT from another domain. TODO Remove when functionality has been in production for some time.
		jwtUtils.getDeletableJwtCookieOnGeneration()
				.ifPresent(deletableJwtCookie ->
						response.addHeader(HttpHeaders.SET_COOKIE, deletableJwtCookie.toString()));

		response.addHeader(HttpHeaders.SET_COOKIE, jwtUtils.getJwtCookie(signedJwt)
				.toString());

		return signedJwt.serialize();
	}


	public void blacklist(JwtTokenInfo jwtTokenInfo) {
		jwtTokenInfo.setBlacklisted(true);
		jwtTokenInfo.setBlacklistedDate(new Timestamp(System.currentTimeMillis()));

		sessionsRepository.findBySessionId(jwtTokenInfo.getLegacySessionId())
				.ifPresent(
						sessionsEntity -> {
							LocalDateTime now = LocalDateTime.now();
							sessionsEntity.setLastModified(now);
							sessionsEntity.setValidTo(now);
							sessionsRepository.saveAndFlush(sessionsEntity);
						});

		jwtTokenInfoRepository.save(jwtTokenInfo);
	}

	public Optional<JwtTokenInfo> findById(UUID id){
		return jwtTokenInfoRepository.findById(id);
	}

	public Optional<List<JwtTokenInfo>> findAllBySessionId(String sessionId) {return  jwtTokenInfoRepository.findAllByLegacySessionId(sessionId);}
}
