package ee.eesti.authentication.configuration;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * scans components from rigs.commons.aop
 */
@Configuration
@EnableAspectJAutoProxy
@ComponentScan(basePackages = {"rig.commons.aop"})
public class AOPConfiguration {

}
