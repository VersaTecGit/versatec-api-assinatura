package com.versatec.safeid;

import com.versatec.domain.JobStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Serviço responsável pelo disparo assíncrono de notificações via webhook.
 * <p>
 * Quando um job de assinatura (SafeID ou futuro NeoID) possui uma {@code webhookUrl}
 * cadastrada, este serviço dispara um {@code POST} para essa URL com o resultado
 * da assinatura após o processamento do callback OAuth2.
 * <p>
 * O disparo é assíncrono ({@link Async}) para não bloquear o processamento do callback.
 * Falhas no webhook são logadas mas não propagam exceção — a integridade do job
 * não deve depender da disponibilidade do sistema cliente.
 */
@Service
public class SafeIdWebhookService {

    private static final Logger log = LoggerFactory.getLogger(SafeIdWebhookService.class);

    private final RestTemplate restTemplate;

    public SafeIdWebhookService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Dispara o webhook de forma assíncrona após a conclusão de um job.
     * <p>
     * O body enviado segue o padrão:
     * <pre>{@code
     * {
     *   "jobId": "...",
     *   "status": "COMPLETED" | "FAILED",
     *   "downloadUrl": "/api/v1/sign/download/{jobId}",  // apenas quando COMPLETED
     *   "errorMessage": "...",                           // apenas quando FAILED
     *   "timestamp": "2024-..."
     * }
     * }</pre>
     *
     * @param webhookUrl   URL de destino registrada pelo sistema cliente
     * @param jobId        identificador do job de assinatura
     * @param status       status final do job ({@code COMPLETED} ou {@code FAILED})
     * @param errorMessage mensagem de erro (preenchida apenas para {@code FAILED})
     */
    @Async
    public void notifyWebhook(String webhookUrl, UUID jobId, JobStatus status, String errorMessage) {
        log.info("Disparando webhook para {} (job {}, status {})", webhookUrl, jobId, status);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("jobId", jobId.toString());
        payload.put("status", status.name());
        payload.put("timestamp", Instant.now().toString());

        if (status == JobStatus.COMPLETED) {
            payload.put("downloadUrl", "/api/v1/sign/download/" + jobId);
        }
        if (status == JobStatus.FAILED && errorMessage != null) {
            payload.put("errorMessage", errorMessage);
        }

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    webhookUrl,
                    payload,
                    String.class
            );
            log.info("Webhook entregue para {} — status HTTP: {}", webhookUrl, response.getStatusCode());
        } catch (Exception e) {
            // Falha no webhook não deve comprometer o processamento do job
            log.error("Falha ao entregar webhook para {} (job {}): {}", webhookUrl, jobId, e.getMessage());
        }
    }
}
