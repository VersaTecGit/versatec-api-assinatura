package com.versatec.safeid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Resposta do endpoint {@code POST /oauth/signature} do SafeID.
 * <p>
 * O array {@code signatures} corresponde, na mesma ordem, ao array {@code hashes}
 * enviado na requisição. Cada item contém o {@code id} do conteúdo assinado e
 * o valor da assinatura em Base64 ({@code raw_signature}).
 *
 * @param certificateAlias alias do certificado utilizado na assinatura
 * @param signatures       lista de assinaturas produzidas
 */
public record SafeIdSignatureResponse(
        @JsonProperty("certificate_alias") String certificateAlias,
        @JsonProperty("signatures")        List<SignatureItem> signatures
) {

    /**
     * Representa a assinatura de um único conteúdo.
     *
     * @param id           identificador do conteúdo assinado (mesmo do request)
     * @param rawSignature valor numérico da assinatura em Base64
     */
    public record SignatureItem(
            @JsonProperty("id")            String id,
            @JsonProperty("raw_signature") String rawSignature
    ) {}
}
