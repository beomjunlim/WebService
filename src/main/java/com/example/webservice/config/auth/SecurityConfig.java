package com.example.webservice.config.auth;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.example.webservice.domain.user.Role;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrfConfig -> csrfConfig.disable())
            .headers(headersConfig -> headersConfig.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable()))
            .authorizeHttpRequests(authorizeHttp -> authorizeHttp.requestMatchers(PathRequest.toH2Console()).permitAll()
                .requestMatchers("/", "/css/**", "/images/**", "/js/**").permitAll()
                .requestMatchers("/api/v1/**").hasRole(Role.USER.name())
                .anyRequest().authenticated())
            .logout(logoutConfig -> logoutConfig.logoutSuccessUrl("/"))
            .oauth2Login(oauth2LoginConfig -> oauth2LoginConfig.userInfoEndpoint(
                userInfoEndpointConfig -> userInfoEndpointConfig.userService(customOAuth2UserService)));

        return http.build();
    }

}
