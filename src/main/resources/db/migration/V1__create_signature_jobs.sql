-- ============================================================
-- Migration: V1__create_signature_jobs.sql
-- Cria a tabela de jobs de assinatura assíncrona (NeoID).
-- ============================================================

CREATE TABLE signature_jobs (
    id                UUID        NOT NULL,
    user_id           VARCHAR(100),
    document_hash     VARCHAR(512) NOT NULL,
    original_file_path TEXT        NOT NULL,
    original_file_name VARCHAR(255) NOT NULL,
    signed_file_path  TEXT,
    signed_file_name  VARCHAR(255),
    status            VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    created_at        TIMESTAMP WITH TIME ZONE  NOT NULL,
    completed_at      TIMESTAMP WITH TIME ZONE,
    expires_at        TIMESTAMP WITH TIME ZONE  NOT NULL,
    error_message     TEXT,

    CONSTRAINT pk_signature_jobs PRIMARY KEY (id),
    CONSTRAINT chk_signature_jobs_status
        CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED', 'EXPIRED'))
);

-- Índice para polling por status (usado pelo endpoint /sign/status e scheduler)
CREATE INDEX idx_signature_jobs_status ON signature_jobs (status);

-- Índice para busca por usuário
CREATE INDEX idx_signature_jobs_user_id ON signature_jobs (user_id);

-- Índice para o scheduler de expiração (busca PENDING + expires_at)
CREATE INDEX idx_signature_jobs_pending_expiry
    ON signature_jobs (status, expires_at);

COMMENT ON TABLE signature_jobs IS
    'Jobs de assinatura digital assíncrona via NeoID (SerproID). '
    'Cada linha representa uma solicitação pendente de aprovação do titular.';

COMMENT ON COLUMN signature_jobs.id IS
    'UUID do job. Também usado como "state" no fluxo OAuth2 para correlacionar o callback.';

COMMENT ON COLUMN signature_jobs.document_hash IS
    'Hash SHA-256 do documento original, codificado em Base64. '
    'Enviado ao endpoint /signature do Serpro para assinatura remota.';

COMMENT ON COLUMN signature_jobs.expires_at IS
    'Timestamp de expiração do job. Jobs PENDING após este tempo são marcados como EXPIRED.';
