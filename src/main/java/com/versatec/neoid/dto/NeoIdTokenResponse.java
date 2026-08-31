package com.versatec.neoid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta do endpoint {@code POST /oauth/token} do NeoID.
 * <p>
 * Mapeamento dos campos retornados pelo Serpro após a troca do
 * {@code authorization_code} pelo {@code access_token}.
 *
 * @param accessToken  token de acesso para chamadas autenticadas (ex: /signature)
 * @param tokenType    tipo do token (geralmente "Bearer")
 * @param expiresIn    tempo de validade do token em segundos
 * @param scope        escopos autorizados pelo titular
 */
public record NeoIdTokenResponse(
        @JsonProperty("access_token")  String accessToken,
        @JsonProperty("token_type")    String tokenType,
        @JsonProperty("expires_in")    Integer expiresIn,
        @JsonProperty("scope")         String scope
) {}
