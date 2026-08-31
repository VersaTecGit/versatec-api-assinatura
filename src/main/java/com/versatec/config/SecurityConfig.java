package com.versatec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http.csrf(AbstractHttpConfigurer::disable)
                                .authorizeHttpRequests(requests -> requests.requestMatchers(
                                                "/api/v1/qr-code",
                                                // Callbacks OAuth2 — obrigatoriamente públicos:
                                                // o browser redireciona para cá após aprovação no app,
                                                // sem contexto de autenticação. A segurança é garantida
                                                // pelo protocolo: code single-use + state=jobId validado
                                                // no banco + PKCE code_verifier (SafeID)
                                                "/api/v1/safeid/callback",
                                                "/api/v1/neoid/callback",
                                                "/swagger-ui/**",
                                                "/swagger/**",
                                                "/v1/api-docs/**").permitAll()
                                                // Status e download exigem autenticação:
                                                // o sistema cliente usa as mesmas credenciais Basic Auth
                                                // que usou para chamar o POST /sign-xml
                                                .anyRequest().authenticated())
                                .httpBasic(Customizer.withDefaults());

                return http.build();
        }
}
