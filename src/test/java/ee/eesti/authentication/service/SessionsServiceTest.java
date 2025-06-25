package ee.eesti.authentication.service;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.enums.Language;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.transaction.annotation.Transactional;

import jakarta.servlet.http.HttpSession;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

class SessionsServiceTest extends AbstractSpringBasedTest {

	private static final ChannelType CHANNEL = ChannelType.AUTENTIMATA;
	private static final String MOBILE_NUMBER = "54545454";
	private static final String FIRST_NAME = "John";
	private static final String LAST_NAME = "Doe";
	private static final String PERSONAL_CODE = "EE38833883383";
	private static final String DEFAULT_IP = "127.0.0.1";

	@Autowired
	SessionsService sessionsService;

	@Autowired
	SessionsRepository sessionsRepository;

	@Mock
	MockHttpServletRequest mockHttpServletRequest;

	@Autowired
	LegacyPortalIntegrationConfig config;

	@BeforeEach
	void init() {
		sessionsRepository.deleteAll();

		HttpSession mockHttpSession = new MockHttpSession();
		mockHttpSession.setAttribute(config.getRequestIpAttribute(), DEFAULT_IP);
		when(mockHttpServletRequest.getSession()).thenReturn(mockHttpSession);
	}

	@Test
	@Transactional
	void createSessionEntity() {

		assertNotNull(mockHttpServletRequest.getSession());

		sessionsService.createSessionEntity(
				getUserInfo(),
				CHANNEL,
				SessionsService.createSessionId(),
				MOBILE_NUMBER,
				getUserOriginIp(mockHttpServletRequest),
				Language.EE.name().toLowerCase(),
				getUserAgentHeader(mockHttpServletRequest));

		List<SessionsEntity> sessionsEntities = sessionsService.getSessionIds();

		assertEquals(1, sessionsEntities.size());
		assertEquals(FIRST_NAME, sessionsEntities.get(0).getGivenname());
		assertEquals(null, sessionsEntities.get(0).getRights());
	}

	@Test
	@Transactional
	void createSessionEntity_NotEstonianResident_ThrowsException() {
		UserInfo userInfo = new UserInfo();
		userInfo.setPersonalCode("LT12345678901");

		String sessionId = SessionsService.createSessionId();
		String userOriginIp = getUserOriginIp(mockHttpServletRequest);
		String userLanguage = Language.EE.name().toLowerCase();
		String userAgentHeader = getUserAgentHeader(mockHttpServletRequest);

		assertThrows(
				IllegalArgumentException.class,
				() -> sessionsService.createSessionEntity(
						userInfo,
						CHANNEL,
						sessionId,
						MOBILE_NUMBER,
						userOriginIp,
						userLanguage,
						userAgentHeader)
		);
	}

	@Test
	@Transactional
	void createLoginSession_SessionDoesNotExist_CreatesNewSession() {
		sessionsService.openLegacyPortalLoginSession(mockHttpServletRequest, getUserInfo(), CHANNEL, MOBILE_NUMBER);

		List<SessionsEntity> sessionsEntities = sessionsService.getSessionIds();

		assertEquals(1, sessionsEntities.size());
	}

	private UserInfo getUserInfo() {
		UserInfo userInfo = new UserInfo();
		userInfo.setFirstName(FIRST_NAME);
		userInfo.setLastName(LAST_NAME);
		userInfo.setPersonalCode(PERSONAL_CODE);
		return userInfo;
	}

	private String getUserOriginIp(MockHttpServletRequest request) {
		return (String) request.getSession().getAttribute(config.getRequestIpAttribute());
	}

	private String getUserAgentHeader(MockHttpServletRequest request) {
		return request.getHeader("User-Agent");
	}

}
