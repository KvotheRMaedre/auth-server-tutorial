package tech.kvothe.auth_server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityFilterConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authServerSecurityChain (HttpSecurity httpSecurity) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer().oidc(withDefaults());

        httpSecurity
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")
                        ))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(withDefaults()))
                .with(authorizationServerConfigurer, withDefaults());

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultServerSecurityChain (HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults());

        return httpSecurity.build();
    }
}
