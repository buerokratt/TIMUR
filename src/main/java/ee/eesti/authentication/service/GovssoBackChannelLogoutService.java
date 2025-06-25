package ee.eesti.authentication.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GovssoBackChannelLogoutService {

    private final GovssoLogoutTokenService govssoLogoutTokenService;
    private final GovssoSessionService govssoSessionService;

    public void endSession(String logoutToken) {
        String govssoSessionId = govssoLogoutTokenService.validateAndParseSessionId(logoutToken);
        govssoSessionService.remove(govssoSessionId);
    }

}
