package ee.eesti.authentication.controller;

import ee.eesti.authentication.aop.Timed;
import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@ConditionalOnProperty(prefix = "custom-error-handling", name = "enabled", matchIfMissing = true)
@Timed
public class CustomErrorController implements ErrorController {

    private static final String ERROR_PATH = "/error";

    @Value("${custom-error-handling.response-status:INTERNAL_SERVER_ERROR}")
    private HttpStatus responseStatus;

    /**
     * @return empty response to ensure no detailed information about internal errors is shown
     */
    @Operation(hidden = true)
    @RequestMapping(value = ERROR_PATH)
    public ResponseEntity<?> whitelabelError() {
        log.warn("Whitelabel error page accessed.");
        return ResponseEntity.status(responseStatus).build();
    }

}
