package com.versatec.safeid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Request para o endpoint {@code POST /oauth/signature} do SafeID.
 * <p>
 * O campo {@code hashes} é um array de objetos estruturados, cada um contendo o hash
 * a ser assinado em Base64, o algoritmo OID, e o formato de assinatura desejado.
 *
 * @param certificateAlias alias do certificado a ser utilizado (opcional)
 * @param hashes           lista de conteúdos a serem assinados
 */
public record SafeIdSignatureRequest(
        @JsonProperty("certificate_alias") String certificateAlias,
        @JsonProperty("hashes")            List<HashItem> hashes
) {

    /**
     * Representa um único item a ser assinado.
     *
     * @param id              identificador único do conteúdo (correlaciona request/response)
     * @param alias           forma legível do identificador
     * @param hash            hash do documento codificado em <b>Base64</b>
     * @param hashAlgorithm   OID do algoritmo de hash (ex: {@code 2.16.840.1.101.3.4.2.1} para SHA-256)
     * @param signatureFormat formato da assinatura: {@code RAW} ou {@code CMS}
     */
    public record HashItem(
            @JsonProperty("id")               String id,
            @JsonProperty("alias")            String alias,
            @JsonProperty("hash")             String hash,
            @JsonProperty("hash_algorithm")   String hashAlgorithm,
            @JsonProperty("signature_format") String signatureFormat
    ) {}
}
