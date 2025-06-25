package ee.eesti.authentication.domain;

import java.time.LocalDateTime;

import ee.eesti.authentication.repository.entity.SessionsEntity;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SessionInfo {
	private Long id;
	private String channel;
	private String sessionId;
	private String personalCode;
	private String authenticatedAs;
	private String hash;
	private LocalDateTime validFrom;
	private LocalDateTime validTo;
	private String givenname;
	private String surname;
	private String params;
	private LocalDateTime created;
	private LocalDateTime lastModified;
	private String ip;
	private String browser;
	private String username;
	private String loginLevel;
	private String mobileNumber;
	private String certificateType;
	private boolean current;

	public static SessionInfo from(SessionsEntity s) {
		return SessionInfo.builder()
				.id(s.getId())
				.channel(s.getChannel())
				.sessionId(s.getSessionId())
				.personalCode(s.getPersonalCode())
				.authenticatedAs(s.getAuthenticatedAs())
				.hash(s.getHash())
				.validFrom(s.getValidFrom())
				.validTo(s.getValidTo())
				.givenname(s.getGivenname())
				.surname(s.getSurname())
				.params(s.getParams())
				.created(s.getCreated())
				.lastModified(s.getLastModified())
				.ip(s.getIp())
				.browser(s.getBrowser())
				.username(s.getUsername())
				.loginLevel(s.getLoginLevel())
				.mobileNumber(s.getMobileNumber())
				.certificateType(s.getCertificateType())
				.current(s.isCurrent())
				.build();
	}
}
