package com.versatec.repository;

import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repositório Spring Data JPA para a entidade {@link SignatureJob}.
 * <p>
 * Fornece acesso aos jobs de assinatura assíncrona (NeoID), incluindo
 * consultas para polling de status e limpeza de jobs expirados.
 */
@Repository
public interface SignatureJobRepository extends JpaRepository<SignatureJob, UUID> {

    /**
     * Busca todos os jobs de um usuário por status.
     * Útil para auditoria e monitoramento.
     */
    List<SignatureJob> findByUserIdAndStatus(String userId, JobStatus status);

    /**
     * Busca jobs PENDING que passaram do tempo de expiração.
     * Usado por um scheduler para marcar jobs como EXPIRED.
     */
    @Query("SELECT j FROM SignatureJob j WHERE j.status = 'PENDING' AND j.expiresAt < :now")
    List<SignatureJob> findExpiredPendingJobs(Instant now);

    /**
     * Marca em lote os jobs PENDING expirados como EXPIRED.
     * Executado pelo scheduler de limpeza.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE SignatureJob j SET j.status = 'EXPIRED' " +
           "WHERE j.status = 'PENDING' AND j.expiresAt < :now")
    int expireOldJobs(Instant now);

    /**
     * Busca todos os jobs criados antes de uma data de corte.
     * Usado pelo scheduler de faxina para remover histórico antigo e arquivos do disco.
     */
    @Query("SELECT j FROM SignatureJob j WHERE j.createdAt < :cutoff")
    List<SignatureJob> findJobsOlderThan(Instant cutoff);
}
