package ee.eesti.authentication.health;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

@RequiredArgsConstructor
@Component
public class GovssoHealthIndicator implements HealthIndicator {

    private final GovssoHealthProperties properties;

    @Override
    public Health health() {
        if (!properties.isEnabled()) {
            return Health.up().withDetail("status", "Disabled").build();
        }
        String url = properties.getUrl();
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(properties.getTimeout());
            connection.setReadTimeout(properties.getTimeout());
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                return Health.up()
                    .withDetail("URL", url)
                    .build();
            } else {
                return Health.down()
                    .withDetail("URL", url)
                    .withDetail("status", responseCode)
                    .withDetail("error", connection.getResponseMessage())
                    .build();
            }
        } catch (IOException e) {
            return Health.down()
                .withDetail("URL", url)
                .withDetail("error", e.getMessage())
                .withDetail("errorType", e.getClass().getSimpleName())
                .build();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

}
