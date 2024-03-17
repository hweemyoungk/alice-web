package cards.alice.web.config;

import cards.alice.common.config.KeycloakRoleConverter;
import cards.alice.common.filters.CsrfCookieFilter;
import cards.alice.common.filters.EmailVerifiedFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
public class OAuth2SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // No session
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        //config.setAllowedOrigins(Collections.singletonList("*"));
                        config.setAllowedOriginPatterns(Collections.singletonList("*"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setExposedHeaders(List.of("Authorization"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }))
                .headers(configurer -> {
                    configurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
                })
                .csrf(configurer -> configurer
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Frontend app script should access cookies
                        .ignoringRequestMatchers("/public/**")
                )
                .addFilterBefore(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/public/**").permitAll()
                )
                // Currently, no endpoint requires JWT but apply default settings
                .addFilterAfter(new EmailVerifiedFilter(), BearerTokenAuthenticationFilter.class)
                .oauth2ResourceServer(configurer -> {
                    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
                    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
                    configurer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter));
                });
        return http.build();
    }
}
