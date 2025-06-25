package ee.eesti.authentication.controller;

import ee.eesti.authentication.aop.Timed;
import ee.eesti.authentication.configuration.govsso.condition.ConditionalOnGovsso;
import ee.eesti.authentication.service.GovssoBackChannelLogoutService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.media.SchemaProperty;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@Timed
@RequiredArgsConstructor
@ConditionalOnGovsso
public class GovssoBackChannelLogoutController {

    private final GovssoBackChannelLogoutService govssoBackChannelLogoutService;

    @Operation(
            summary = "Back-channel logout",
            description = """
                    Perform back-channel logout as specified by \
                    https://e-gov.github.io/GOVSSO/TechnicalSpecification#65-back-channel-logout-request
                    """)
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", content = @Content, description = "Back-channel logout succeeded or session not found"),
            @ApiResponse(responseCode = "500", content = @Content, description = "Failed to process request"),
    })
    @RequestBody(content = {
            @Content(mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                    schema = @Schema(type = "object"),
                    schemaProperties = {
                            @SchemaProperty(name = "logout_token", schema = @Schema(type = "string"))
                    })
    })
    @PostMapping(value = "/back-channel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> backChannelLogout(
            // Mark parameter as hidden from OpenAPI as it is mistakenly recognised as query param
            // TODO Add separate class BackChannelLogoutRequest and use @RequestBody here to simplify OpenAPI annotations.
            @Parameter(hidden = true) @RequestParam(name = "logout_token") String logoutToken
    ) {
        log.debug("Received GovSSO back-channel logout request with logout token: {}", logoutToken);
        try {
            govssoBackChannelLogoutService.endSession(logoutToken);
        } catch (Exception e) {
            log.error("Failed to end GovSSO session via back-channel logout", e);
            ResponseEntity.internalServerError().build();
        }
        return ResponseEntity.ok().build();
    }
}
