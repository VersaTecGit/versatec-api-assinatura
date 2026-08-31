package com.versatec.safeid;

import com.versatec.customs.FileLocationEnum;
import com.versatec.domain.SignatureJob;
import com.versatec.domain.SignatureType;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Testes unitários para {@link SafeIdSignatureStrategy}.
 * <p>
 * Valida que a strategy inicia o fluxo assíncrono corretamente:
 * calcula o hash, gera PKCE, persiste o job e retorna Pending com a URL.
 */
@ExtendWith(MockitoExtension.class)
class SafeIdSignatureStrategyTest {

    @Mock
    private SafeIdOAuthService oAuthService;

    @Mock
    private SafeIdPkceUtils pkceUtils;

    @Mock
    private SignatureJobRepository jobRepository;

    private SafeIdSignatureStrategy strategy;
    private FileUtils fileUtils;
    private Path xmlFilePath;

    private static final String FAKE_CODE_VERIFIER = "fake-code-verifier-longo-suficiente-pkce";
    private static final String FAKE_CODE_CHALLENGE = "fake-code-challenge-s256";
    private static final String FAKE_AUTH_URL = "https://pscsafeweb.safewebpss.com.br/authorize?state=xxx";

    @BeforeEach
    void setUp() throws Exception {
        strategy = new SafeIdSignatureStrategy(oAuthService, pkceUtils, jobRepository);
        fileUtils = new FileUtils(FileStoragePropertiesMock.create());

        // Cria arquivo XML de teste
        xmlFilePath = fileUtils.getFilePath("safeid-test.xml", FileLocationEnum.ASSET);
        Files.write(xmlFilePath, "<root>conteudo xml</root>".getBytes(StandardCharsets.UTF_8));

        // Mocks do PKCE e OAuth — lenient() evita UnnecessaryStubbing em testes
        // que não usam esses mocks (ex: supports_shouldReturnSAFEID)
        lenient().when(pkceUtils.generateCodeVerifier()).thenReturn(FAKE_CODE_VERIFIER);
        lenient().when(pkceUtils.generateCodeChallenge(FAKE_CODE_VERIFIER)).thenReturn(FAKE_CODE_CHALLENGE);
        lenient().when(oAuthService.buildAuthorizationUrl(any(UUID.class), eq(FAKE_CODE_CHALLENGE)))
                .thenReturn(FAKE_AUTH_URL);
    }

    @AfterEach
    void tearDown() throws IOException {
        fileUtils.removeFile(xmlFilePath);
    }

    @Test
    void signXml_shouldReturnPendingResult() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", null, null);

        SignatureResult result = strategy.signXml(command);

        assertInstanceOf(SignatureResult.Pending.class, result,
                "SafeID deve retornar Pending (fluxo assíncrono)");
    }

    @Test
    void signXml_shouldPersistJobWithPendingStatus() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", "user-abc", null);

        strategy.signXml(command);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());

        SignatureJob job = captor.getValue();
        assertEquals(com.versatec.domain.JobStatus.PENDING, job.getStatus());
        assertEquals("contrato.xml", job.getOriginalFileName());
        assertEquals("user-abc", job.getUserId());
    }

    @Test
    void signXml_shouldPersistCodeVerifierInJob() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", null, null);

        strategy.signXml(command);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());

        assertEquals(FAKE_CODE_VERIFIER, captor.getValue().getCodeVerifier(),
                "O code_verifier PKCE deve ser salvo no job para uso no callback");
    }

    @Test
    void signXml_shouldPersistDeferredDocumentHash() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", null, null);

        strategy.signXml(command);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());

        String hash = captor.getValue().getDocumentHash();
        assertNotNull(hash, "O hash do documento deve estar presente no job");
        assertEquals("DEFERRED", hash, "Hash deve ser DEFERRED pois o calculo XAdES acontece no callback");
    }

    @Test
    void signXml_shouldPersistWebhookUrl() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", null, "https://minha-app.com/webhook");

        strategy.signXml(command);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());
        assertEquals("https://minha-app.com/webhook", captor.getValue().getWebhookUrl());
    }

    @Test
    void signXml_shouldPersistReturnUrl() throws Exception {
        var command = new SignXmlCommand(
                xmlFilePath, "contrato.xml", null, false, null,
                "user-abc", null, "https://minha-app.com/sucesso");

        strategy.signXml(command);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());
        assertEquals("https://minha-app.com/sucesso", captor.getValue().getReturnUrl());
    }

    @Test
    void signXml_pendingResult_shouldContainGeneratedJobId() throws Exception {
        var command = buildCommand(xmlFilePath, "contrato.xml", null, null);

        SignatureResult.Pending result = (SignatureResult.Pending) strategy.signXml(command);

        assertNotNull(result.jobId(), "O jobId não deve ser null");
    }

    @Test
    void supports_shouldReturnSAFEID() {
        assertEquals(SignatureType.SAFEID, strategy.supports(),
                "A strategy deve declarar suporte a SAFEID");
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private SignXmlCommand buildCommand(Path path, String fileName, String userId, String webhookUrl) {
        return new SignXmlCommand(path, fileName, null, false, null, userId, webhookUrl, null);
    }
}
