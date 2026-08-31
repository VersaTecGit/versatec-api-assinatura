package com.versatec.signature.dto;

/**
 * Resultado discriminado de uma operação de assinatura.
 * <p>
 * Usa {@code sealed interface} para forçar o tratamento explícito de
 * ambos os casos no controller via {@code switch} de pattern matching.
 * <p>
 * - {@link Completed}: assinatura síncrona (A1) — documento pronto na resposta.
 * - {@link Pending}:   assinatura assíncrona (NeoID) — aguarda aprovação do titular.
 */
public sealed interface SignatureResult
        permits SignatureResult.Completed, SignatureResult.Pending {

    /**
     * Assinatura concluída de forma síncrona.
     * Retornada pela estratégia A1.
     *
     * @param document o conteúdo do documento assinado em bytes
     * @param fileName nome sugerido para o arquivo na resposta HTTP
     */
    record Completed(byte[] document, String fileName) implements SignatureResult {}

    /**
     * Assinatura iniciada de forma assíncrona.
     * Retornada pela estratégia NeoID.
     *
     * @param jobId            identificador do job para polling e download posterior
     * @param authorizationUrl URL OAuth2 que o titular deve abrir no aplicativo NeoID
     */
    record Pending(java.util.UUID jobId, String authorizationUrl) implements SignatureResult {}
}
