package com.versatec.signature.orchestrator;

import com.versatec.customs.FileLocationEnum;
import com.versatec.neoid.NeoIdApiException;
import com.versatec.neoid.NeoIdOAuthService;
import com.versatec.neoid.dto.NeoIdSignatureResponse;
import com.versatec.neoid.dto.NeoIdTokenResponse;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.UUID;

/**
 * Orquestra o processamento do callback OAuth2 recebido do Serpro NeoID.
 * <p>
 * Executado quando o titular aprova a assinatura no aplicativo móvel e o Serpro
 * redireciona para {@code GET /api/v1/neoid/callback?code=...&state=jobId}.
 * <p>
 * Fluxo completo:
 * <ol>
 *   <li>Localiza o {@link com.versatec.domain.SignatureJob} pelo jobId (state OAuth2).</li>
 *   <li>Troca o {@code authorization_code} pelo {@code access_token}.</li>
 *   <li>Envia o hash SHA-256 (já armazenado no job) ao endpoint {@code /v1/signature} do Serpro.</li>
 *   <li>Persiste o XML assinado no sistema de arquivos.</li>
 *   <li>Atualiza o job para {@link com.versatec.domain.JobStatus#COMPLETED} ou {@code FAILED}.</li>
 * </ol>
 */
@Service
public class NeoIdCallbackOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(NeoIdCallbackOrchestrator.class);

    private final NeoIdOAuthService oAuthService;
    private final SignatureJobRepository jobRepository;
    private final FileUtils fileUtils;

    public NeoIdCallbackOrchestrator(NeoIdOAuthService oAuthService,
                                      SignatureJobRepository jobRepository,
                                      FileUtils fileUtils) {
        this.oAuthService = oAuthService;
        this.jobRepository = jobRepository;
        this.fileUtils = fileUtils;
    }

    /**
     * Processa o callback do Serpro após aprovação do titular.
     *
     * @param code  authorization_code recebido do Serpro
     * @param jobId UUID do job (parâmetro {@code state} do OAuth2)
     */
    @Transactional
    public void process(String code, UUID jobId) {
        log.info("Processando callback NeoID para o job {}", jobId);

        var job = jobRepository.findById(jobId)
                .orElseThrow(() -> {
                    log.error("Job {} não encontrado no callback do NeoID", jobId);
                    return new NeoIdApiException("Job não encontrado: " + jobId);
                });

        if (!job.isPending()) {
            log.warn("Job {} já está com status {}. Callback ignorado.", jobId, job.getStatus());
            return;
        }

        try {
            // Passo 1 — Troca code por access_token
            NeoIdTokenResponse tokenResponse = oAuthService.exchangeCodeForToken(code);
            if (tokenResponse == null || tokenResponse.accessToken() == null) {
                throw new NeoIdApiException("access_token nulo retornado pelo Serpro");
            }

            // Passo 2 — Envia o hash do documento para assinatura remota
            byte[] documentHash = Base64.getDecoder().decode(job.getDocumentHash());
            NeoIdSignatureResponse signatureResponse =
                    oAuthService.sendHashForSignature(tokenResponse.accessToken(), documentHash);

            if (signatureResponse == null || signatureResponse.signature() == null) {
                throw new NeoIdApiException("Assinatura nula retornada pelo Serpro");
            }

            // Passo 3 — Persiste o XML assinado no disco
            byte[] signedContent = Base64.getDecoder().decode(signatureResponse.signature());
            String signedFileName = buildSignedFileName(job.getOriginalFileName());
            Path signedFilePath = fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);
            Files.write(signedFilePath, signedContent);

            // Passo 4 — Atualiza o job para COMPLETED
            job.complete(signedFilePath.toString(), signedFileName);
            jobRepository.save(job);

            log.info("Job {} concluído com sucesso. Arquivo salvo em '{}'", jobId, signedFilePath);

        } catch (NeoIdApiException e) {
            log.error("Falha na comunicação com NeoID para o job {}: {}", jobId, e.getMessage());
            job.fail(e.getMessage());
            jobRepository.save(job);
            throw e;

        } catch (IOException e) {
            String msg = "Erro ao salvar o arquivo assinado: " + e.getMessage();
            log.error("Erro de I/O no processamento do job {}: {}", jobId, e.getMessage());
            job.fail(msg);
            jobRepository.save(job);
            throw new NeoIdApiException(msg, e);

        } catch (Exception e) {
            String msg = "Erro inesperado no processamento do callback: " + e.getMessage();
            log.error("Erro inesperado no job {}: {}", jobId, e.getMessage());
            job.fail(msg);
            jobRepository.save(job);
            throw new NeoIdApiException(msg, e);
        }
    }

    /**
     * Adiciona o sufixo {@code _assinado} ao nome do arquivo antes da extensão.
     * Exemplo: {@code contrato.xml} → {@code contrato_assinado.xml}
     */
    private String buildSignedFileName(String originalFileName) {
        int dotIndex = originalFileName.lastIndexOf('.');
        if (dotIndex != -1) {
            return originalFileName.substring(0, dotIndex)
                    + "_assinado"
                    + originalFileName.substring(dotIndex);
        }
        return originalFileName + "_assinado";
    }
}
