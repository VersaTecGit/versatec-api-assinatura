package com.versatec.safeid;

import com.versatec.domain.SignatureJob;
import com.versatec.domain.SignatureType;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.signature.strategy.SignatureStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * Estratégia de assinatura via <b>Certificado A3 em Nuvem (SafeID/Safeweb PSC)</b>.
 * <p>
 * O fluxo é <b>assíncrono com PKCE</b>: esta estratégia apenas inicia o processo,
 * calculando o hash do documento, gerando as credenciais PKCE, persistindo o job
 * e retornando a URL de autorização OAuth2 para que o titular aprove no aplicativo SafeID.
 * <p>
 * A conclusão ocorre no {@link com.versatec.signature.orchestrator.SafeIdCallbackOrchestrator}
 * quando o SafeID redireciona para o endpoint de callback.
 */
@Component
public class SafeIdSignatureStrategy implements SignatureStrategy {

    private static final Logger log = LoggerFactory.getLogger(SafeIdSignatureStrategy.class);

    private final SafeIdOAuthService oAuthService;
    private final SafeIdPkceUtils pkceUtils;
    private final SignatureJobRepository jobRepository;

    public SafeIdSignatureStrategy(SafeIdOAuthService oAuthService,
                                   SafeIdPkceUtils pkceUtils,
                                   SignatureJobRepository jobRepository) {
        this.oAuthService = oAuthService;
        this.pkceUtils = pkceUtils;
        this.jobRepository = jobRepository;
    }

    /**
     * Inicia o processo de assinatura via SafeID.
     * <ol>
     *   <li>Calcula o hash SHA-256 do arquivo.</li>
     *   <li>Gera o par PKCE ({@code code_verifier} / {@code code_challenge}).</li>
     *   <li>Persiste o {@link SignatureJob} com status {@code PENDING}, incluindo
     *       o {@code codeVerifier}, {@code webhookUrl} e {@code returnUrl} se informados.</li>
     *   <li>Gera a URL de autorização OAuth2 do SafeID.</li>
     *   <li>Retorna {@link SignatureResult.Pending} com o jobId e a URL.</li>
     * </ol>
     *
     * @param command deve ter {@code filePath} e {@code originalFileName} preenchidos.
     *                {@code certificate} é ignorado (null esperado).
     *                {@code userId} é usado para rastreabilidade.
     * @return {@link SignatureResult.Pending} com jobId e authorizationUrl
     */
    @Override
    public SignatureResult signXml(SignXmlCommand command) throws Exception {
        log.info("Iniciando assinatura SafeID para o arquivo '{}'", command.originalFileName());

        // O hash real só será calculado no callback, pois o Demoiselle (XAdES) exige 
        // o certificado público do titular para gerar o hash do <ds:SignedInfo>.
        String hashBase64 = "DEFERRED";

        // 2. Gera par PKCE
        String codeVerifier = pkceUtils.generateCodeVerifier();
        String codeChallenge = pkceUtils.generateCodeChallenge(codeVerifier);

        // 3. Persiste o job com status PENDING
        UUID jobId = UUID.randomUUID();
        SignatureJob job = SignatureJob.builder()
                .id(jobId)
                .userId(command.userId())
                .documentHash(hashBase64)
                .originalFilePath(command.filePath().toString())
                .originalFileName(command.originalFileName())
                .codeVerifier(codeVerifier)
                .webhookUrl(command.webhookUrl())
                .returnUrl(command.returnUrl())
                .build();
        jobRepository.save(job);

        log.info("SignatureJob SafeID {} criado com status PENDING para o arquivo '{}'",
                jobId, command.originalFileName());

        // 4. Gera URL de autorização OAuth2 com PKCE
        String authUrl = oAuthService.buildAuthorizationUrl(jobId, codeChallenge);

        return new SignatureResult.Pending(jobId, authUrl);
    }

    @Override
    public SignatureType supports() {
        return SignatureType.SAFEID;
    }
}
