package com.versatec.domain;

/**
 * Representa o ciclo de vida de um job de assinatura assíncrona (NeoID).
 * <p>
 * - {@link #PENDING}: Job criado, aguardando autorização do titular no aplicativo NeoID.
 * - {@link #COMPLETED}: Assinatura realizada com sucesso. Documento disponível para download.
 * - {@link #FAILED}: Falha durante o processo de assinatura (erro no Serpro ou callback inválido).
 * - {@link #EXPIRED}: O titular não aprovou dentro do tempo limite (TTL).
 */
public enum JobStatus {
    PENDING,
    COMPLETED,
    FAILED,
    EXPIRED
}
