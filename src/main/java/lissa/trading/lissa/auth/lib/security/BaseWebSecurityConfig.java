package lissa.trading.lissa.auth.lib.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Base configuration class for web security.
 * This class sets up the security filter chain and provides methods for custom security configurations.
 */
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public abstract class BaseWebSecurityConfig {

    private final BaseAuthTokenFilter<?> authTokenFilter;

    /**
     * Configures the security filter chain.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain baseFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/swagger-ui/*", "/v3/api-docs/*").permitAll()  // Allow access to Swagger UI and API docs
                        .requestMatchers("/v1/internal/**").hasRole("INTERNAL_SERVICE") // Restrict internal requests to users with INTERNAL_SERVICE role
                );

        configureHttpSecurity(http);

        anyRequestConfiguration(http);

        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Override this method to add custom HTTP security configurations.
     *
     * @param http the HttpSecurity object to configure
     * @throws Exception if an error occurs during configuration
     */
    protected void configureHttpSecurity(HttpSecurity http) throws Exception {
        // Override this method to add custom configuration
    }

    /**
     * Configures the security settings for any other requests.
     *
     * @param http the HttpSecurity object to configure
     * @throws Exception if an error occurs during configuration
     */
    protected void anyRequestConfiguration(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated() // Require authentication for any other requests
        );
    }
}