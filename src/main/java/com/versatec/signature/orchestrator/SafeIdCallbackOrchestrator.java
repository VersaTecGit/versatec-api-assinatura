package com.versatec.signature.orchestrator;

import com.versatec.customs.FileLocationEnum;
import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.safeid.SafeIdApiException;
import com.versatec.safeid.SafeIdOAuthService;
import com.versatec.safeid.SafeIdWebhookService;
import com.versatec.safeid.dto.SafeIdSignatureResponse;
import com.versatec.safeid.dto.SafeIdTokenResponse;
import com.versatec.utils.FileUtils;
import com.versatec.utils.XmlSignatureRelocator;
import com.versatec.customs.XmlNodeNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Orquestra o processamento do callback OAuth2 recebido do SafeID (Safeweb PSC).
 * <p>
 * Executado quando o titular aprova a assinatura no aplicativo SafeID e o PSC
 * redireciona para {@code GET /api/v1/safeid/callback?code=...&state=jobId}.
 * <p>
 * Fluxo completo:
 * <ol>
 *   <li>Localiza o {@link SignatureJob} pelo jobId (parâmetro {@code state} OAuth2).</li>
 *   <li>Recupera o {@code code_verifier} PKCE armazenado no job.</li>
 *   <li>Troca o {@code authorization_code} + {@code code_verifier} pelo {@code access_token}.</li>
 *   <li>Envia o hash SHA-256 (armazenado no job) ao endpoint {@code /oauth/signature} do SafeID.</li>
 *   <li>Persiste o arquivo assinado no sistema de arquivos.</li>
 *   <li>Atualiza o job para {@link JobStatus#COMPLETED} ou {@code FAILED}.</li>
 *   <li>Notifica via webhook assíncrono (se configurado).</li>
 * </ol>
 *
 * <p><b>Retorno para o navegador:</b> o método {@link #process} retorna opcionalmente
 * uma {@code returnUrl}, para que o controller possa redirecionar o navegador do usuário
 * após o processamento.
 */
@Service
public class SafeIdCallbackOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(SafeIdCallbackOrchestrator.class);

    private final SafeIdOAuthService oAuthService;
    private final SafeIdWebhookService webhookService;
    private final SignatureJobRepository jobRepository;
    private final FileUtils fileUtils;
    private final XmlSignatureRelocator relocator;

    public SafeIdCallbackOrchestrator(SafeIdOAuthService oAuthService,
                                      SafeIdWebhookService webhookService,
                                      SignatureJobRepository jobRepository,
                                      FileUtils fileUtils,
                                      XmlSignatureRelocator relocator) {
        this.oAuthService = oAuthService;
        this.webhookService = webhookService;
        this.jobRepository = jobRepository;
        this.fileUtils = fileUtils;
        this.relocator = relocator;
    }

    /**
     * Processa o callback do SafeID após aprovação do titular.
     *
     * @param code  authorization_code recebido do SafeID
     * @param jobId UUID do job (parâmetro {@code state} do OAuth2)
     * @return {@code returnUrl} configurada no job, ou {@code null} se não houver
     */
    @Transactional
    public String process(String code, UUID jobId) {
        log.info("Processando callback SafeID para o job {}", jobId);

        SignatureJob job = jobRepository.findById(jobId)
                .orElseThrow(() -> {
                    log.error("Job {} não encontrado no callback do SafeID", jobId);
                    return new SafeIdApiException("Job não encontrado: " + jobId);
                });

        if (!job.isPending()) {
            log.warn("Job {} já está com status {}. Callback ignorado.", jobId, job.getStatus());
            return job.getReturnUrl();
        }

        // Verifica se o code_verifier PKCE está presente
        if (job.getCodeVerifier() == null || job.getCodeVerifier().isBlank()) {
            String msg = "code_verifier PKCE ausente no job " + jobId + ". Não é possível trocar o código.";
            log.error(msg);
            failJob(job, msg);
            return job.getReturnUrl();
        }

        try {
            // Passo 1 — Troca code + code_verifier por access_token
            SafeIdTokenResponse tokenResponse = oAuthService.exchangeCodeForToken(code, job.getCodeVerifier());
            if (tokenResponse == null || tokenResponse.accessToken() == null) {
                throw new SafeIdApiException("access_token nulo retornado pelo SafeID");
            }

            // Passo 2 — Obtém o certificado do usuário
            String certBase64 = oAuthService.getCertificateInfo(tokenResponse.accessToken());
            // Limpa cabeçalhos PEM e quebras de linha caso a string venha formatada
            String cleanCertBase64 = certBase64
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "")
                    .replace('-', '+')
                    .replace('_', '/');

            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate userCert = cf.generateCertificate(
                    new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cleanCertBase64))
            );

            // Passo 3 — Prepara Demoiselle (XMLSigner)
            org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner xmlSigner = createXmlSigner();
            xmlSigner.setCertificateChain(new java.security.cert.Certificate[]{userCert});
            
            // Injeta a chave remota que o nosso VersatecProvider vai interceptar
            com.versatec.signature.async.RemotePrivateKey remoteKey = new com.versatec.signature.async.RemotePrivateKey(
                    tokenResponse.accessToken(), oAuthService, jobId
            );
            xmlSigner.setPrivateKey(remoteKey);

            // Garante que o provedor interceptador está registrado
            if (java.security.Security.getProvider("Versatec") == null) {
                java.security.Security.insertProviderAt(new com.versatec.signature.async.VersatecProvider(), 1);
            }

            // Passo 4 — Executa a assinatura XAdES síncrona
            // Isso fará o Demoiselle montar o XML, chamar nosso VersatecProvider (RemoteSignatureSpi),
            // que fará a chamada HTTP para o SafeID e retornará a assinatura RAW.
            byte[] fileContent = Files.readAllBytes(Path.of(job.getOriginalFilePath()));
            org.w3c.dom.Document signedDocument = xmlSigner.signEnveloped(fileContent);

            relocator.relocate(signedDocument, job.getTargetXPath());

            // Converte o Document assinado de volta para bytes
            byte[] signedContent;
            try (java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream()) {
                javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
                // Prevenição de SSRF via XXE no TransformerFactory
                tf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
                tf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
                javax.xml.transform.Transformer transformer = tf.newTransformer();
                transformer.transform(
                        new javax.xml.transform.dom.DOMSource(signedDocument),
                        new javax.xml.transform.stream.StreamResult(outputStream));
                signedContent = outputStream.toByteArray();
            }

            // Passo 5 — Persiste o arquivo XML final no disco
            String signedFileName = buildSignedFileName(job.getOriginalFileName());
            Path signedFilePath = fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);
            Files.write(signedFilePath, signedContent);

            // Passo 6 — Atualiza o job para COMPLETED
            job.complete(signedFilePath.toString(), signedFileName);
            jobRepository.save(job);
            log.info("Job SafeID {} concluído com sucesso. Arquivo XAdES salvo em '{}'", jobId, signedFilePath);

            // Passo 7 — Dispara webhook assíncrono se configurado
            if (job.getWebhookUrl() != null && !job.getWebhookUrl().isBlank()) {
                webhookService.notifyWebhook(job.getWebhookUrl(), jobId, JobStatus.COMPLETED, null);
            }

        } catch (SafeIdApiException e) {
            log.error("Falha na comunicação com SafeID para o job {}: {}", jobId, e.getMessage());
            failJobAndNotify(job, e.getMessage());
            throw e;

        } catch (XmlNodeNotFoundException e) {
            String msg = "O nó especificado pelo targetXPath (" + job.getTargetXPath() + ") não foi encontrado. O XML pode ter sido modificado desde a requisição inicial.";
            log.error("Erro no job {}: {}", jobId, msg);
            failJobAndNotify(job, msg);
            throw new SafeIdApiException(msg, e);
            
        } catch (Exception e) {
            String msg = "Erro inesperado no processamento do callback: " + e.getMessage();
            log.error("Erro inesperado no job {}: {}", jobId, e.getMessage());
            failJobAndNotify(job, msg);
            throw new SafeIdApiException(msg, e);
        }

        return job.getReturnUrl();
    }

    // -------------------------------------------------------------------------
    // Helpers privados
    // -------------------------------------------------------------------------


    private void failJob(SignatureJob job, String message) {
        job.fail(message);
        jobRepository.save(job);
    }

    private void failJobAndNotify(SignatureJob job, String message) {
        failJob(job, message);
        if (job.getWebhookUrl() != null && !job.getWebhookUrl().isBlank()) {
            webhookService.notifyWebhook(job.getWebhookUrl(), job.getId(), JobStatus.FAILED, message);
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

    public org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner createXmlSigner() {
        return new org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner();
    }
}
