package ee.eesti.authentication.connector;

import ee.eesti.authentication.domain.RepresentableParty;
import ee.eesti.authentication.domain.RightsRepresentablePartiesResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.function.Predicate;

import static ee.eesti.authentication.handlers.RestExceptionHandler.ERROR_ID_HEADER_KEY;

@Slf4j
@Service
@RequiredArgsConstructor
public class RightsClient {

    private final WebClient rightsWebClient;

    @Value("${jwt-integration.signature.cookie-name}")
    private String userJwtCookieName;

    public RightsRepresentablePartiesResponse getRepresentableParties(String userJwt, String language) {
        var responseBuilder = RightsRepresentablePartiesResponse.builder();
        List<RepresentableParty> representableParties = rightsWebClient.get()
                .uri("/representable-parties?lang={language}", language)
                .cookie(userJwtCookieName, userJwt)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(Predicate.not(HttpStatusCode::is2xxSuccessful), clientResponse -> handleErrorResponse(clientResponse, "representable parties"))
                .toEntity(new ParameterizedTypeReference<List<RepresentableParty>>() {
                })
                .mapNotNull(response -> {
                    if (response.getHeaders().containsKey(ERROR_ID_HEADER_KEY)) {
                        responseBuilder.errorId(response.getHeaders().getFirst(ERROR_ID_HEADER_KEY));
                    }
                    responseBuilder.status(response.getStatusCode().value());
                    return response.getBody();
                })
                .block();
        return responseBuilder.representableParties(representableParties).build();
    }

    private Mono<RightsClientException> handleErrorResponse(ClientResponse clientResponse, String endpoint) {
        return clientResponse.bodyToMono(String.class)
                .defaultIfEmpty("NO BODY")
                .flatMap(errorBody -> {
                    log.warn("Unexpected " + endpoint + " response - statusCode: {}, body: {}", clientResponse.statusCode(), errorBody);
                    return Mono.error(new RightsClientException("Unexpected " + endpoint + " response: %s".formatted(clientResponse.statusCode())));
                });
    }

    public void evictUserCache(String userJwt) {
        rightsWebClient.post()
                .uri("/cache/user/evict")
                .cookie(userJwtCookieName, userJwt)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(Predicate.not(HttpStatusCode::is2xxSuccessful), clientResponse -> handleErrorResponse(clientResponse, "user cache evict"))
                .bodyToMono(Void.class).block();
    }
}
