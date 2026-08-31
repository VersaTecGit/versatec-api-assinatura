package com.versatec.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/**
 * Representa um job de assinatura assíncrona via NeoID (SerproID) ou SafeID (Safeweb).
 * <p>
 * O ciclo de vida de um job:
 * <ol>
 *   <li>{@link JobStatus#PENDING}   — criado ao receber a requisição, aguardando aprovação no celular.</li>
 *   <li>{@link JobStatus#COMPLETED} — assinatura concluída, documento disponível para download.</li>
 *   <li>{@link JobStatus#FAILED}    — falha durante o processo (erro do Serpro ou callback inválido).</li>
 *   <li>{@link JobStatus#EXPIRED}   — titular não aprovou dentro do tempo limite.</li>
 * </ol>
 */
@Entity
@Table(name = "signature_jobs")
public class SignatureJob {

    /** Identificador único do job. Também usado como {@code state} no fluxo OAuth2. */
    @Id
    @Column(columnDefinition = "uuid", updatable = false, nullable = false)
    private UUID id;

    /**
     * Identificador do usuário/sistema que solicitou a assinatura.
     * Usado para rastreabilidade e auditoria.
     */
    @Column(name = "user_id", length = 100)
    private String userId;

    /**
     * Hash SHA-256 do documento original, enviado ao Serpro para assinatura.
     * Armazenado em Base64.
     */
    @Column(name = "document_hash", nullable = false, length = 512)
    private String documentHash;

    /**
     * Caminho do arquivo original no servidor (temporário até conclusão).
     */
    @Column(name = "original_file_path", nullable = false)
    private String originalFilePath;

    /**
     * Nome original do arquivo enviado pelo cliente.
     */
    @Column(name = "original_file_name", nullable = false, length = 255)
    private String originalFileName;

    /**
     * Caminho do arquivo assinado no servidor.
     * Preenchido apenas quando {@code status == COMPLETED}.
     */
    @Column(name = "signed_file_path")
    private String signedFilePath;

    /**
     * Nome do arquivo assinado (ex: "documento_assinado.xml").
     * Preenchido apenas quando {@code status == COMPLETED}.
     */
    @Column(name = "signed_file_name", length = 255)
    private String signedFileName;

    /** Status atual do job. */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private JobStatus status;

    /** Timestamp de criação do job. */
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /** Timestamp de conclusão (sucesso ou falha). Nulo enquanto PENDING. */
    @Column(name = "completed_at")
    private Instant completedAt;

    /**
     * Timestamp de expiração do job.
     * Jobs PENDING que ultrapassarem este tempo devem ser marcados como EXPIRED.
     * Padrão: criação + 15 minutos.
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * Mensagem de erro em caso de falha.
     * Preenchida quando {@code status == FAILED}.
     */
    @Column(name = "error_message")
    private String errorMessage;

    /**
     * {@code code_verifier} PKCE gerado durante a autorização SafeID (RFC 7636).
     * <p>
     * Armazenado temporariamente para uso no callback. <b>Nulo para jobs NeoID e A1.</b>
     */
    @Column(name = "code_verifier", length = 128)
    private String codeVerifier;

    /**
     * URL de webhook a ser notificada após a conclusão do job (sucesso ou falha).
     * <p>
     * Se preenchida, nossa API dispara um {@code POST} assíncrono ao concluir o job.
     * <b>Opcional.</b> Aplicável a SafeID e NeoID.
     */
    @Column(name = "webhook_url", length = 2048)
    private String webhookUrl;

    /**
     * URL de redirecionamento após o processamento do callback OAuth2.
     * <p>
     * Se preenchida, nossa API executa um {@code 302 Redirect} para esta URL
     * com os parâmetros {@code ?jobId=...&status=...} ao concluir o callback.
     * <b>Opcional.</b> Aplicável a SafeID e NeoID.
     */
    @Column(name = "return_url", length = 2048)
    private String returnUrl;

    protected SignatureJob() {}

    private SignatureJob(Builder builder) {
        this.id = builder.id;
        this.userId = builder.userId;
        this.documentHash = builder.documentHash;
        this.originalFilePath = builder.originalFilePath;
        this.originalFileName = builder.originalFileName;
        this.status = builder.status;
        this.createdAt = builder.createdAt;
        this.expiresAt = builder.expiresAt;
        this.codeVerifier = builder.codeVerifier;
        this.webhookUrl = builder.webhookUrl;
        this.returnUrl = builder.returnUrl;
    }

    public static Builder builder() {
        return new Builder();
    }

    // --- Métodos de negócio ---

    /**
     * Marca o job como concluído com sucesso.
     *
     * @param signedFilePath caminho do arquivo assinado gerado
     * @param signedFileName nome do arquivo assinado
     */
    public void complete(String signedFilePath, String signedFileName) {
        this.status = JobStatus.COMPLETED;
        this.signedFilePath = signedFilePath;
        this.signedFileName = signedFileName;
        this.completedAt = Instant.now();
    }

    /**
     * Marca o job como falho, registrando a mensagem de erro.
     *
     * @param errorMessage descrição do erro ocorrido
     */
    public void fail(String errorMessage) {
        this.status = JobStatus.FAILED;
        this.errorMessage = errorMessage;
        this.completedAt = Instant.now();
    }

    /** @return true se o job ainda aguarda aprovação */
    public boolean isPending() {
        return this.status == JobStatus.PENDING;
    }

    /** @return true se o job foi concluído com sucesso */
    public boolean isCompleted() {
        return this.status == JobStatus.COMPLETED;
    }

    // --- Getters ---

    public UUID getId() { return id; }
    public String getUserId() { return userId; }
    public String getDocumentHash() { return documentHash; }
    public String getOriginalFilePath() { return originalFilePath; }
    public String getOriginalFileName() { return originalFileName; }
    public String getSignedFilePath() { return signedFilePath; }
    public String getSignedFileName() { return signedFileName; }
    public JobStatus getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getCompletedAt() { return completedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public String getErrorMessage() { return errorMessage; }
    public String getCodeVerifier() { return codeVerifier; }
    public String getWebhookUrl() { return webhookUrl; }
    public String getReturnUrl() { return returnUrl; }

    // --- Builder ---

    public static class Builder {
        private UUID id;
        private String userId;
        private String documentHash;
        private String originalFilePath;
        private String originalFileName;
        private JobStatus status = JobStatus.PENDING;
        private Instant createdAt = Instant.now();
        private Instant expiresAt = Instant.now().plusSeconds(900); // 15 min padrão
        private String codeVerifier;
        private String webhookUrl;
        private String returnUrl;

        public Builder id(UUID id) { this.id = id; return this; }
        public Builder userId(String userId) { this.userId = userId; return this; }
        public Builder documentHash(String documentHash) { this.documentHash = documentHash; return this; }
        public Builder originalFilePath(String originalFilePath) { this.originalFilePath = originalFilePath; return this; }
        public Builder originalFileName(String originalFileName) { this.originalFileName = originalFileName; return this; }
        public Builder status(JobStatus status) { this.status = status; return this; }
        public Builder createdAt(Instant createdAt) { this.createdAt = createdAt; return this; }
        public Builder expiresAt(Instant expiresAt) { this.expiresAt = expiresAt; return this; }
        public Builder codeVerifier(String codeVerifier) { this.codeVerifier = codeVerifier; return this; }
        public Builder webhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; return this; }
        public Builder returnUrl(String returnUrl) { this.returnUrl = returnUrl; return this; }

        public SignatureJob build() {
            if (id == null) id = UUID.randomUUID();
            return new SignatureJob(this);
        }
    }
}
