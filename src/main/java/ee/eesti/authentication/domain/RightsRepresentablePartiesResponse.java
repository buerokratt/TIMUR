package ee.eesti.authentication.domain;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Response can have 2xx status code and also have errorId.
 * For example business representatives request failed on background, but user can still represent himself.
 * View: https://rig-rights.dev.riaint.ee/swagger-ui/index.html#/Rights/getJwtRepresentableParties
 */
@Data
@Builder
public class RightsRepresentablePartiesResponse {
    private List<RepresentableParty> representableParties;
    private int status;
    private String errorId;
}
