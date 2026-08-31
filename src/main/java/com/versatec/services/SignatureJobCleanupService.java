package com.versatec.services;

import com.versatec.domain.SignatureJob;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Serviço responsável por tarefas de manutenção agendadas para os jobs do NeoID.
 * <p>
 * Executa periodicamente:
 * 1. Expiração de jobs pendentes que ultrapassaram o tempo limite (15 min).
 * 2. Limpeza de jobs antigos (concluídos, falhos ou expirados) e remoção de seus arquivos do disco.
 */
@Service
public class SignatureJobCleanupService {

    private static final Logger log = LoggerFactory.getLogger(SignatureJobCleanupService.class);

    private final SignatureJobRepository jobRepository;
    private final FileUtils fileUtils;
    private final int retentionDays;

    public SignatureJobCleanupService(
            SignatureJobRepository jobRepository,
            FileUtils fileUtils,
            @Value("${neoid.job.retention-days:7}") int retentionDays) {
        this.jobRepository = jobRepository;
        this.fileUtils = fileUtils;
        this.retentionDays = retentionDays;
    }

    /**
     * Expira periodicamente os jobs pendentes cujo tempo limite (expiresAt) já foi atingido.
     * Padrão: executa a cada 5 minutos (300.000 ms), configurável via neoid.job.expire-interval.
     */
    @Scheduled(fixedDelayString = "${neoid.job.expire-interval:300000}")
    @Transactional
    public void expirePendingJobs() {
        Instant now = Instant.now();
        int expiredCount = jobRepository.expireOldJobs(now);
        if (expiredCount > 0) {
            log.info("Expiração automática: {} job(s) PENDING marcados como EXPIRED.", expiredCount);
        }
    }

    /**
     * Purga jobs mais antigos que o período de retenção configurado (retentionDays).
     * Remove os arquivos originais e assinados do disco antes de deletar os registros do banco.
     * Padrão: executa todos os dias às 03:00 da manhã.
     */
    @Scheduled(cron = "${neoid.job.cleanup-cron:0 0 3 * * *}")
    @Transactional
    public void purgeOldJobs() {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        List<SignatureJob> oldJobs = jobRepository.findJobsOlderThan(cutoff);

        if (oldJobs.isEmpty()) {
            return;
        }

        log.info("Iniciando limpeza de histórico: {} job(s) anteriores a {} serão purgados.", oldJobs.size(), cutoff);

        for (SignatureJob job : oldJobs) {
            deletePhysicalFileQuietly(job.getOriginalFilePath());
            deletePhysicalFileQuietly(job.getSignedFilePath());
        }

        jobRepository.deleteAll(oldJobs);
        log.info("Limpeza concluída com sucesso: {} job(s) removidos do banco de dados.", oldJobs.size());
    }

    private void deletePhysicalFileQuietly(String filePathStr) {
        if (filePathStr != null && !filePathStr.isBlank()) {
            try {
                fileUtils.removeFile(Path.of(filePathStr));
            } catch (Exception e) {
                log.warn("Falha ao remover arquivo físico durante faxina: {} - Erro: {}", filePathStr, e.getMessage());
            }
        }
    }
}
