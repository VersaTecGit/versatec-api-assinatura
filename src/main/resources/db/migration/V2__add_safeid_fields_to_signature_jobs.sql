-- ============================================================
-- Migration: V2__add_safeid_fields_to_signature_jobs.sql
-- Adiciona colunas para suporte ao fluxo SafeID (Safeweb PSC):
--   - code_verifier: PKCE (RFC 7636), usado apenas em jobs SafeID
--   - webhook_url:   URL para notificacao assincrona ao cliente
--   - return_url:    URL de redirecionamento do navegador apos o callback
--
-- Todas as colunas sao NULLABLE para nao impactar jobs NeoID
-- e A1 existentes.
-- ============================================================

ALTER TABLE signature_jobs ADD COLUMN code_verifier VARCHAR(128);
ALTER TABLE signature_jobs ADD COLUMN webhook_url VARCHAR(2048);
ALTER TABLE signature_jobs ADD COLUMN return_url VARCHAR(2048);

-- Atualiza comentario da tabela para refletir os novos provedores
COMMENT ON TABLE signature_jobs IS
    'Jobs de assinatura digital assincrona. Suporta NeoID (SerproID) e SafeID (Safeweb PSC). '
    'Cada linha representa uma solicitacao pendente de aprovacao do titular.';

COMMENT ON COLUMN signature_jobs.code_verifier IS
    'Verifier PKCE (RFC 7636) gerado ao iniciar o fluxo SafeID. '
    'Obrigatorio para trocar o authorization_code por access_token. '
    'NULL para jobs NeoID e A1.';

COMMENT ON COLUMN signature_jobs.webhook_url IS
    'URL de webhook para notificacao POST assincrona apos conclusao do job. '
    'Opcional. Aplicavel a SafeID e NeoID.';

COMMENT ON COLUMN signature_jobs.return_url IS
    'URL de redirecionamento HTTP 302 apos o processamento do callback OAuth2. '
    'Util para SPAs e apps mobile. Opcional.';
