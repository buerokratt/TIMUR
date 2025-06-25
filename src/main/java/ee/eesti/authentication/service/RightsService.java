package ee.eesti.authentication.service;

import com.nimbusds.jwt.SignedJWT;
import ee.eesti.authentication.configuration.jwt.JwtUtils;
import ee.eesti.authentication.connector.RightsClient;
import ee.eesti.authentication.connector.RightsClientException;
import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.RightsRepresentablePartiesResponse;
import ee.eesti.authentication.domain.SelectRepresentablePartyByCodeRequest;
import ee.eesti.authentication.domain.UserInfo;
import ee.eesti.authentication.repository.JwtTokenInfoRepository;
import ee.eesti.authentication.repository.entity.JwtTokenInfo;
import org.apache.commons.collections4.CollectionUtils;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RightsService {

    public static final Long CITIZEN_INSTITUTION_ID = 0L;

    private final RightsClient rightsClient;
    private final JwtUtils jwtUtils;

    private final JwtTokenInfoService jwtTokenInfoService;
    private final JwtTokenInfoRepository jwtTokenInfoRepository;


    /**
     * Returns representable parties in requested language that the provided user is allowed to select
     *
     * @param language language
     * @return representable parties
     */
    public RightsRepresentablePartiesResponse getRepresentableParties(String jwt, String language) {
        return rightsClient.getRepresentableParties(jwt, language);
    }

    public Optional<RepresentableParty> findRepresentableParty(String jwt, String representativeCode) {
        return CollectionUtils.emptyIfNull(getRepresentableParties(jwt, "et").getRepresentableParties()).stream()
                .filter(party -> party.getCode().equals(representativeCode))
                .findFirst();
    }

    public boolean hasRepresentableParty(UserInfo userInfo, String jwt) {
        return userInfo.getPersonalCode().equals(userInfo.getRepresentedParty().getCode())
                || findRepresentableParty(jwt, userInfo.getRepresentedParty().getCode()).isPresent();
    }


    public String selectRepresentativeByCode(
            String jwtFromCookie,
            SelectRepresentablePartyByCodeRequest selectPartyRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        Optional<RepresentableParty> selectedParty = findRepresentableParty(jwtFromCookie,
                selectPartyRequest.getCode());
        if (selectedParty.isEmpty()) {
            log.warn("No representable party found for provided party code: {}", selectPartyRequest.getCode());
            throw new IllegalArgumentException("Bad representative identifier input for representative selection");
        }
        return selectRepresentative(jwtFromCookie, selectedParty.get(), request, response);
    }


    @SneakyThrows
    private String selectRepresentative(
            String jwtFromCookie,
            RepresentableParty selectedRepresentative,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        UserInfo userInfoFromJwt = jwtUtils.getUserInfo(jwtFromCookie);

        if (userInfoFromJwt == null) {
            throw new IllegalArgumentException("No existing user info to update");
        }

        SignedJWT parse = SignedJWT.parse(jwtFromCookie);
        String oldJwtId = parse.getJWTClaimsSet().getJWTID();

        JwtTokenInfo jwtTokenInfo = jwtTokenInfoRepository
                .findById(UUID.fromString(oldJwtId))
                .orElseThrow(() -> new IllegalArgumentException("old jwt token info is not found for blacklisting"));

        userInfoFromJwt.setRepresentedParty(selectedRepresentative);

        jwtTokenInfoService.blacklist(jwtTokenInfo);
        return jwtTokenInfoService.extendSessionObtainedFromJwt(oldJwtId, userInfoFromJwt, request, response);
    }

    public void evictUserCache(String jwt) {
        try {
            rightsClient.evictUserCache(jwt);
        }
        catch (RightsClientException e) {
            log.warn("Failed to evict user rig-rights cache - {}", e.getMessage());
        }
        catch (Exception e) {
            log.error("Failed to evict user rig-rights cache", e);
        }
    }

}
