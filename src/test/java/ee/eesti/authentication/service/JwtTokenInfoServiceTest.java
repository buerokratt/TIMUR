package ee.eesti.authentication.service;

import ee.eesti.AbstractSpringBasedTest;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtTokenInfoServiceTest extends AbstractSpringBasedTest {

	private static final String DEFAULT_SESSION_ID_1 = "q6pzhtnlb0vppk2s1kj8jbz6rw003tvb";
	private static final String DEFAULT_SESSION_ID_2 = "q6pzhtnlb0vppk2s1kj8jbz6rw003tvc";
	private static final UUID DEFAULT_JWT_TOKEN = UUID.randomUUID();

	@Autowired
	JwtTokenInfoService jwtTokenInfoService;

	@Autowired
	JwtTokenInfoRepository jwtTokenInfoRepository;

	@BeforeEach
	void init() {
		jwtTokenInfoRepository.deleteAll();
	}

	@Test
	@Transactional
	void createJwtTokenInfo() {
		// using sessionId and jwtToken
		jwtTokenInfoService.createJwtTokenInfo(DEFAULT_JWT_TOKEN, DEFAULT_SESSION_ID_1, new Timestamp(new Date().getTime() + 1000 * 60 * 30));

		// using sessionId only
		jwtTokenInfoService.createJwtTokenInfo(UUID.randomUUID(), DEFAULT_SESSION_ID_2, new Timestamp(new Date().getTime() + 1000 * 60 * 30));

		assertEquals(2, jwtTokenInfoRepository.findAll().size());
	}
}
