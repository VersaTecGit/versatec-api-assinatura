package com.versatec.safeid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta do endpoint {@code POST /oauth/token} do SafeID.
 * <p>
 * Além dos campos padrão OAuth2, o SafeID inclui informações do titular
 * ({@code authorized_identification_type} e {@code authorized_identification})
 * que identificam o CPF ou CNPJ do certificado utilizado.
 *
 * @param accessToken                 token Bearer para uso nos endpoints de assinatura
 * @param tokenType                   valor fixo {@code Bearer}
 * @param expiresIn                   validade do token em segundos (máx. PF: 7 dias, PJ: 30 dias)
 * @param scope                       escopo concedido (pode diferir do solicitado)
 * @param authorizedIdentificationType tipo do identificador do titular: {@code CPF} ou {@code CNPJ}
 * @param authorizedIdentification    número do CPF/CNPJ do titular que autorizou
 */
public record SafeIdTokenResponse(
        @JsonProperty("access_token")                   String accessToken,
        @JsonProperty("token_type")                     String tokenType,
        @JsonProperty("expires_in")                     int expiresIn,
        @JsonProperty("scope")                          String scope,
        @JsonProperty("authorized_identification_type") String authorizedIdentificationType,
        @JsonProperty("authorized_identification")      String authorizedIdentification
) {}
