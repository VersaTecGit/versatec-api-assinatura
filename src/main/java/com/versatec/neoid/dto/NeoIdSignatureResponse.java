package com.versatec.neoid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Resposta do endpoint {@code POST /v1/signature} do NeoID.
 * <p>
 * Contém o CMS (Cryptographic Message Syntax) com a assinatura digital
 * gerada pelo certificado A3 do titular, em Base64.
 *
 * @param signature    assinatura CMS em Base64 gerada pelo Serpro
 * @param signatureAlgorithm algoritmo utilizado na assinatura
 */
public record NeoIdSignatureResponse(
        @JsonProperty("signature")          String signature,
        @JsonProperty("signatureAlgorithm") String signatureAlgorithm
) {}
