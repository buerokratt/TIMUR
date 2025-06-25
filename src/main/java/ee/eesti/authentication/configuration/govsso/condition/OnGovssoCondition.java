package ee.eesti.authentication.configuration.govsso.condition;

import ee.eesti.authentication.enums.AuthenticationProvider;
import lombok.NonNull;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class OnGovssoCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, @NonNull AnnotatedTypeMetadata metadata) {
        AuthenticationProvider authenticationProvider =
                context.getEnvironment().getProperty("auth.provider", AuthenticationProvider.class);
        return authenticationProvider == AuthenticationProvider.GOVSSO;
    }

}
