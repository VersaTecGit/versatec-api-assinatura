package com.versatec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * Configuração dos clientes HTTP da aplicação.
 * <p>
 * Registra um {@link RestTemplate} como bean Spring para ser injetado
 * nos serviços que realizam chamadas REST externas (ex: {@link com.versatec.neoid.NeoIdOAuthService}).
 */
@Configuration
public class HttpClientConfig {

    /**
     * Bean {@link RestTemplate} padrão para chamadas HTTP síncronas.
     * <p>
     * Futuramente pode ser configurado com timeouts e interceptors de logging
     * sem impactar os serviços que o injetam.
     */
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
