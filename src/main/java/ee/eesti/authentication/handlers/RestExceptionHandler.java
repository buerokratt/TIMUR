package ee.eesti.authentication.handlers;

import ee.eesti.authentication.domain.ExceptionResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.UUID;

@Slf4j
@ControllerAdvice
@ConditionalOnProperty(prefix = "custom-error-handling", name = "enabled", matchIfMissing = true)
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    public static final String ERROR_ID_HEADER_KEY = "Rig-Error-Id";

    @Value("${custom-error-handling.response-status:INTERNAL_SERVER_ERROR}")
    private HttpStatus responseStatus;

    @ExceptionHandler(value = Throwable.class)
    public ResponseEntity<Object> doHandle(Exception e) {
        UUID errorId = UUID.randomUUID();
        log.error(String.format("Exception has occurred uuid=%s", errorId), e);
        return ResponseEntity
                .status(responseStatus.value())
                .header(ERROR_ID_HEADER_KEY, errorId.toString())
                .body(new ExceptionResponse(errorId));
    }

}
