package com.versatec.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Propriedades de configuração para integração com o NeoID (SerproID).
 * <p>
 * As credenciais {@code clientId} e {@code clientSecret} são fornecidas pelo Serpro
 * após o credenciamento da aplicação no Portal de Serviços.
 * <p>
 * Configure via variáveis de ambiente:
 * <pre>
 *   NEOID_CLIENT_ID=seu_client_id
 *   NEOID_CLIENT_SECRET=seu_client_secret
 *   APP_URL=https://sua-api.com
 * </pre>
 */
@Configuration
@ConfigurationProperties(prefix = "neoid")
public class NeoIdProperties {

    /**
     * Identificador da aplicação (fornecido pelo Serpro após credenciamento).
     * Variável de ambiente: {@code NEOID_CLIENT_ID}
     */
    private String clientId;

    /**
     * Segredo da aplicação (fornecido pelo Serpro após credenciamento).
     * Variável de ambiente: {@code NEOID_CLIENT_SECRET}
     */
    private String clientSecret;

    /**
     * Endpoint de autorização OAuth2 do NeoID.
     * Padrão: https://neoid.estaleiro.serpro.gov.br/oauth/authorize
     */
    private String authorizationEndpoint;

    /**
     * Endpoint de troca de código por token OAuth2.
     * Padrão: https://neoid.estaleiro.serpro.gov.br/oauth/token
     */
    private String tokenEndpoint;

    /**
     * Endpoint de envio do hash para assinatura.
     * Padrão: https://neoid.estaleiro.serpro.gov.br/v1/signature
     */
    private String signatureEndpoint;

    /**
     * URL de callback pública desta API, para onde o Serpro redirecionará
     * após a aprovação do titular. Deve ser acessível externamente pelo Serpro.
     * Exemplo: https://sua-api.com/api/v1/neoid/callback
     */
    private String callbackUrl;

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getAuthorizationEndpoint() { return authorizationEndpoint; }
    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }

    public String getSignatureEndpoint() { return signatureEndpoint; }
    public void setSignatureEndpoint(String signatureEndpoint) {
        this.signatureEndpoint = signatureEndpoint;
    }

    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
}
