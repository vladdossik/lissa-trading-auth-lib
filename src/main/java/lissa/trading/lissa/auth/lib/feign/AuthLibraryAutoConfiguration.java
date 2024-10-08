package lissa.trading.lissa.auth.lib.feign;

import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableFeignClients(basePackageClasses = AuthServiceClient.class)
public class AuthLibraryAutoConfiguration {
}
