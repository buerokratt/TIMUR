package ee.eesti.authentication.configuration;

import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import ee.eesti.authentication.constant.AuthSuccessRedirectProperties;
import ee.eesti.authentication.constant.LegacyPortalIntegrationConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OFFLINE_ACCESS;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;

/**
 * this filter is set up to add session attributes depending on information from request
 */
@Component
@RequiredArgsConstructor
public class CustomSessionAttributeSecurityFilter extends GenericFilterBean {

    public static final String CALLBACK_URL = "callback_url";

    private final LegacyPortalIntegrationConfig config;

    private final AuthSuccessRedirectProperties authSuccessRedirectProperties;

	/**
	 * Ensures that callback_url request parameter is in whitelist. Stores callback_url as session attribute.
	 * Also if session has no request ip attribute set it will be set from request header
	 *
	 *
	 * @param request incoming request
	 * @param response current response
	 * @param chain filter chain to continue to
	 * @throws IOException
	 * @throws ServletException
	 *
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpSession session = ((HttpServletRequest)request).getSession();
		HttpServletResponse res = (HttpServletResponse) response;

		if (request.getParameter(CALLBACK_URL) != null) {

			if(!callBackUrlAllowed(request.getParameter(CALLBACK_URL))) {
				logger.error("Callback url " + request.getParameter(CALLBACK_URL) + " is not in the allowed list");
				res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Callback url is not in allowed list");
				return;
			}

			session.setAttribute(CALLBACK_URL, request.getParameter(CALLBACK_URL));
		}

		if (session.getAttribute(config.getRequestIpAttribute()) == null) {
			String ip = ((HttpServletRequest) request).getHeader(config.getRequestIpHeader());
			if (ip == null || "".equals(ip)) {
				ip = request.getRemoteAddr();
			}
			session.setAttribute(config.getRequestIpAttribute() , ip);
		}

        if (hasScope(request, OFFLINE_ACCESS)) {
			session.setAttribute(SCOPE, OFFLINE_ACCESS.toString());
        }

        chain.doFilter(request, response);
    }

    private static boolean hasScope(ServletRequest request, OIDCScopeValue scopeValue) {
        return request.getParameter(SCOPE) != null && Arrays.stream(request.getParameter(SCOPE).split(" ")).anyMatch(it -> it.equals(scopeValue.getValue()));
    }

    private boolean callBackUrlAllowed(String url) {
        return authSuccessRedirectProperties.getWhitelist().contains(url.trim());
    }

}
