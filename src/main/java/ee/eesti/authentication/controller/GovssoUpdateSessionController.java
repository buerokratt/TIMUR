package ee.eesti.authentication.controller;

import ee.eesti.authentication.aop.Timed;
import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import ee.eesti.authentication.service.GovssoUpdateSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@Timed
@ConditionalOnGovsso
public class GovssoUpdateSessionController {

    private final GovssoUpdateSessionService govssoUpdateSessionService;

    @Builder
    public GovssoUpdateSessionController(GovssoUpdateSessionService govssoUpdateSessionService) {
        this.govssoUpdateSessionService = govssoUpdateSessionService;
    }

    @PostMapping("/oauth2/refresh/govsso")
    public ResponseEntity<Void> updateGovssoSession(HttpServletRequest request, HttpServletResponse response) {
        return govssoUpdateSessionService.updateGovssoSession(request, response);
    }
}
