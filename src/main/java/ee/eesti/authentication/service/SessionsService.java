package ee.eesti.authentication.service;

import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.enums.ChannelType;
import ee.eesti.authentication.enums.Language;
import ee.eesti.authentication.repository.SessionsRepository;
import ee.eesti.authentication.repository.entity.SessionsEntity;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;
import ee.eesti.authentication.aop.Timed;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Manages sessions.
 */
@Service
@Slf4j
@Timed
public class SessionsService {

    private final SessionsRepository sessionRepository;

    private final LegacyPortalIntegrationConfig config;

    public SessionsService(SessionsRepository sessionRepository, LegacyPortalIntegrationConfig config) {
        this.sessionRepository = sessionRepository;
        this.config = config;
    }

    /**
     * Login. Returns a SessionsEntity containing information about active session.
     * @param user  contains user information
     * @param sessionId session's id
     * @param mobilenumber  mobile number
     * @param userOriginIp ip of user's login
     * @param userLanguage user's language
     * @param userAgentHeader user agent string
     *
     *
     * @throws IllegalArgumentException if user does not have an Estonian personal code
     * @return contains information about sessions
     */
    public SessionsEntity createSessionEntity(UserInfo user,
                                              ChannelType channel,
                                              String sessionId,
                                              String mobilenumber,
                                              String userOriginIp,
                                              String userLanguage,
                                              String userAgentHeader) {

        if (!user.isHasEstonianPersonalCode()) {
            throw new IllegalArgumentException("cannot create entity for not EE resident. PersonalCode: " + user.getPersonalCode());
        }

        SessionsEntity sessionEntity = sessionRepository.findBySessionId(sessionId).orElse(new SessionsEntity());

        LocalDateTime currentTimestamp = LocalDateTime.now();

        String personalCode = user.getPersonalCode().replaceAll("\\D", "");
        sessionEntity.setChannel(channel.getChannel());
        sessionEntity.setSessionId(sessionId);
        sessionEntity.setPersonalCode(personalCode);
        sessionEntity.setAuthenticatedAs(user.getAuthenticatedAs());
        sessionEntity.setHash(user.getHash());
        sessionEntity.setUsername(personalCode);
        sessionEntity.setValidFrom(currentTimestamp);
        sessionEntity.setValidTo(currentTimestamp.plusMinutes(config.getSessionTimeoutMinutes()));
        sessionEntity.setGivenname(user.getFirstName());
        sessionEntity.setSurname(user.getLastName());
        sessionEntity.setMobileNumber(mobilenumber);

        sessionEntity.setParams(String.format("{{LANG, %s},{XMLHTTP,YES}}", userLanguage));

        sessionEntity.setCreated(currentTimestamp);
        sessionEntity.setLastModified(currentTimestamp);

        sessionEntity.setIp(userOriginIp);
        sessionEntity.setBrowser(userAgentHeader);

        String loginlevel = channel.getLoginLevel();
        sessionEntity.setLoginLevel(loginlevel);

        sessionEntity = sessionRepository.saveAndFlush(sessionEntity);
        log.info("sessionEntity created with id :{}", sessionEntity.getId());

        return sessionEntity;
    }

    /**
     *
     * @return new UUID, similar to  java.util UUID with the "-" characters removed
     */
    public static String createSessionId() {
        return UUID.randomUUID().toString().toLowerCase().replace("-", "");
    }


    /**
     * Login. Starts a legacy session.
     * @param request incoming request
     * @param user contains user's info
     * @param channel enumerated selection of possible channels
     * @param mobileNumber mobile number
     * @return  contains information about session
     */
    public SessionsEntity openLegacyPortalLoginSession(HttpServletRequest request, UserInfo user, ChannelType channel,
                                                       String mobileNumber) {
        String userOriginIp = "";
        String languageCode = Language.EE.name().toLowerCase();

        if (request.getSession(false) != null) {
            userOriginIp = (String) request.getSession(false).getAttribute(config.getRequestIpAttribute());
        } else {
            log.warn("session for given request not found");
        }

        String sessionId = createSessionId();

        return createSessionEntity(
                user,
                channel,
                sessionId,
                mobileNumber,
                userOriginIp,
                languageCode,
                request.getHeader("User-Agent"));
    }

    /**
     * @return all sessions
     */
    public List<SessionsEntity> getSessionIds() {
        return sessionRepository.findAll();
    }


}
