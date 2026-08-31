package com.versatec.neoid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Payload enviado ao endpoint {@code POST /v1/signature} do NeoID.
 * <p>
 * O Serpro espera receber o hash SHA-256 do documento em Base64,
 * junto com os metadados da operação.
 *
 * @param hash          hash SHA-256 do documento codificado em Base64
 * @param hashAlgorithm algoritmo usado para calcular o hash (padrão: "SHA-256")
 */
public record NeoIdSignatureRequest(
        @JsonProperty("hash")           String hash,
        @JsonProperty("hashAlgorithm")  String hashAlgorithm
) {
    /**
     * Construtor de conveniência com algoritmo padrão SHA-256.
     *
     * @param hash hash SHA-256 do documento em Base64
     */
    public NeoIdSignatureRequest(String hash) {
        this(hash, "SHA-256");
    }
}
