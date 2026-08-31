package com.versatec.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Propriedades de configuração para integração com o SafeID (Safeweb PSC).
 * <p>
 * As credenciais {@code clientId} e {@code clientSecret} são fornecidas pela Safeweb
 * após o cadastro da aplicação no portal de integração.
 * <p>
 * Configure via variáveis de ambiente:
 * <pre>
 *   SAFEID_CLIENT_ID=seu_client_id
 *   SAFEID_CLIENT_SECRET=seu_client_secret
 *   APP_URL=https://sua-api.com
 * </pre>
 */
@Configuration
@ConfigurationProperties(prefix = "safeid")
public class SafeIdProperties {

    /**
     * Identificador da aplicação (fornecido pela Safeweb após cadastro).
     * Variável de ambiente: {@code SAFEID_CLIENT_ID}
     */
    private String clientId;

    /**
     * Segredo da aplicação (fornecido pela Safeweb após cadastro).
     * Variável de ambiente: {@code SAFEID_CLIENT_SECRET}
     */
    private String clientSecret;

    /**
     * Endpoint de autorização OAuth2 do SafeID.
     * Padrão: https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth/authorize
     */
    private String authorizationEndpoint;

    /**
     * Endpoint de troca de código por token OAuth2.
     * Padrão: https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth/token
     */
    private String tokenEndpoint;

    /**
     * Endpoint de envio do hash para assinatura remota.
     * Padrão: https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth/signature
     */
    private String signatureEndpoint;

    /**
     * URL de callback pública desta API, registrada no portal Safeweb.
     * O SafeID redirecionará para esta URL após aprovação do titular.
     * Exemplo: https://sua-api.com/api/v1/safeid/callback
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
    public void setSignatureEndpoint(String signatureEndpoint) { this.signatureEndpoint = signatureEndpoint; }

    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }
}
