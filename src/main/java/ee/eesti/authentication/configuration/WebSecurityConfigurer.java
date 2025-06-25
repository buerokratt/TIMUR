package ee.eesti.authentication.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@RequiredArgsConstructor
@Configuration
public class WebSecurityConfigurer {

    @Value("${headers.content-security-policy}")
    private String contentSecurityPolicy;

    private final CustomSessionAttributeSecurityFilter filter;

    private final Customizer<OAuth2LoginConfigurer<HttpSecurity>> oAuth2LoginConfigurer;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .csrf(AbstractHttpConfigurer::disable) // needed for JWT verification
                .cors(withDefaults())
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(contentSecurityPolicy)))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(antMatcher("/v3/api-docs"),
                                antMatcher("/v3/api-docs.yaml"),
                                antMatcher("/v3/api-docs/swagger-config"),
                                antMatcher("/swagger-ui.html"),
                                antMatcher("/swagger-ui/**"),
                                antMatcher("/webjars/**"),
                                antMatcher("/actuator/**"),
                                antMatcher("/cancel-auth"),
                                antMatcher("/back-channel-logout"),
                                antMatcher("/v2/jwt/**"),
                                antMatcher("/jwt/**"),
                                antMatcher("/oauth2/refresh/govsso"))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .logout(AbstractHttpConfigurer::disable)
                .addFilterBefore(filter, OAuth2AuthorizationRequestRedirectFilter.class)
                .oauth2Login(oAuth2LoginConfigurer)
                /* While we're turning off automatically changing session IDs on successful authentication,
                 * we are doing that manually in AuthenticationSuccessHandlers. This is done because automatic
                 * session ID update would trigger on GovSSO session update, but we don't want that.
                 */
                .sessionManagement(management -> management
                        .sessionFixation()
                        .none());
        // @formatter:on
        return http.build();
    }

}
