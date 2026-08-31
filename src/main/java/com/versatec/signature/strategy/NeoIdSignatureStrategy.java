package com.versatec.signature.strategy;

import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import com.versatec.domain.SignatureType;
import com.versatec.neoid.NeoIdOAuthService;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * Estratégia de assinatura via <b>Certificado A3 em Nuvem (NeoID/SerproID)</b>.
 * <p>
 * O fluxo é <b>assíncrono</b>: esta estratégia apenas inicia o processo,
 * calculando o hash do documento, persistindo o job e retornando a URL
 * de autorização OAuth2 para que o titular aprove no aplicativo móvel.
 * <p>
 * A conclusão da assinatura ocorre no {@link com.versatec.signature.orchestrator.NeoIdCallbackOrchestrator}
 * quando o Serpro chama o endpoint de callback.
 */
@Component
public class NeoIdSignatureStrategy implements SignatureStrategy {

    private static final Logger log = LoggerFactory.getLogger(NeoIdSignatureStrategy.class);

    private final NeoIdOAuthService oAuthService;
    private final SignatureJobRepository jobRepository;

    public NeoIdSignatureStrategy(NeoIdOAuthService oAuthService,
                                   SignatureJobRepository jobRepository) {
        this.oAuthService = oAuthService;
        this.jobRepository = jobRepository;
    }

    /**
     * Inicia o processo de assinatura via NeoID.
     * <ol>
     *   <li>Calcula o hash SHA-256 do arquivo XML.</li>
     *   <li>Persiste o {@link SignatureJob} com status {@link JobStatus#PENDING}.</li>
     *   <li>Gera a URL de autorização OAuth2 do Serpro.</li>
     *   <li>Retorna {@link SignatureResult.Pending} com o jobId e a URL.</li>
     * </ol>
     *
     * @param command deve ter {@code filePath} e {@code originalFileName} preenchidos.
     *                {@code certificate} é ignorado (null esperado).
     * @return {@link SignatureResult.Pending} com jobId e authorizationUrl
     */
    @Override
    public SignatureResult signXml(SignXmlCommand command) throws Exception {
        log.info("Iniciando assinatura NeoID para o arquivo '{}'", command.originalFileName());

        // 1. Calcula hash SHA-256 do documento
        byte[] content = Files.readAllBytes(command.filePath());
        byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(content);
        String hashBase64 = Base64.getEncoder().encodeToString(hashBytes);

        // 2. Persiste o job com status PENDING
        UUID jobId = UUID.randomUUID();
        SignatureJob job = SignatureJob.builder()
                .id(jobId)
                .userId(command.userId())
                .documentHash(hashBase64)
                .originalFilePath(command.filePath().toString())
                .originalFileName(command.originalFileName())
                .build();
        jobRepository.save(job);

        log.info("SignatureJob {} criado com status PENDING para o arquivo '{}'",
                jobId, command.originalFileName());

        // 3. Gera URL de autorização OAuth2 (state = jobId)
        String authUrl = oAuthService.buildAuthorizationUrl(jobId);

        return new SignatureResult.Pending(jobId, authUrl);
    }

    @Override
    public SignatureType supports() {
        return SignatureType.NEOID;
    }
}
