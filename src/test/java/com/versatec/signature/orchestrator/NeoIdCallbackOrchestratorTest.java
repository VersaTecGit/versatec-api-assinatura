package com.versatec.signature.orchestrator;

import com.versatec.customs.FileLocationEnum;
import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.neoid.NeoIdApiException;
import com.versatec.neoid.NeoIdOAuthService;
import com.versatec.neoid.dto.NeoIdSignatureResponse;
import com.versatec.neoid.dto.NeoIdTokenResponse;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NeoIdCallbackOrchestratorTest {

    @Mock
    private NeoIdOAuthService oAuthService;

    @Mock
    private SignatureJobRepository jobRepository;

    private NeoIdCallbackOrchestrator orchestrator;
    private FileUtils fileUtils;
    private Path tempXmlPath;

    @BeforeEach
    void setUp() throws Exception {
        fileUtils = new FileUtils(FileStoragePropertiesMock.create());
        orchestrator = new NeoIdCallbackOrchestrator(oAuthService, jobRepository, fileUtils);

        // Cria arquivo XML temporário para simular o documento original
        tempXmlPath = fileUtils.getFilePath("original.xml", FileLocationEnum.ASSET);
        Files.write(tempXmlPath, "<root/>".getBytes(StandardCharsets.UTF_8));
    }

    @AfterEach
    void tearDown() throws IOException {
        fileUtils.removeFile(tempXmlPath);
    }

    private SignatureJob buildPendingJob(UUID jobId) {
        String hash = Base64.getEncoder().encodeToString("fakehash".getBytes());
        return SignatureJob.builder()
                .id(jobId)
                .userId("user-1")
                .documentHash(hash)
                .originalFilePath(tempXmlPath.toString())
                .originalFileName("original.xml")
                .build();
    }

    @Test
    void process_shouldCompleteJobSuccessfully() throws IOException {
        UUID jobId = UUID.randomUUID();
        SignatureJob job = buildPendingJob(jobId);

        byte[] fakeSignedContent = "<signed/>".getBytes(StandardCharsets.UTF_8);
        String signatureBase64 = Base64.getEncoder().encodeToString(fakeSignedContent);

        when(jobRepository.findById(jobId)).thenReturn(Optional.of(job));
        when(oAuthService.exchangeCodeForToken("valid-code"))
                .thenReturn(new NeoIdTokenResponse("my-token", "Bearer", 3600, "signature"));
        when(oAuthService.sendHashForSignature(anyString(), any(byte[].class)))
                .thenReturn(new NeoIdSignatureResponse(signatureBase64, "SHA256withRSA"));

        orchestrator.process("valid-code", jobId);

        assertEquals(JobStatus.COMPLETED, job.getStatus());
        assertNotNull(job.getSignedFilePath());
        assertNotNull(job.getCompletedAt());
        verify(jobRepository, atLeastOnce()).save(job);

        // Cleanup do arquivo assinado gerado
        if (job.getSignedFilePath() != null) {
            Files.deleteIfExists(Path.of(job.getSignedFilePath()));
        }
    }

    @Test
    void process_whenJobNotFound_shouldThrowNeoIdApiException() {
        UUID jobId = UUID.randomUUID();
        when(jobRepository.findById(jobId)).thenReturn(Optional.empty());

        assertThrows(NeoIdApiException.class,
                () -> orchestrator.process("code", jobId));
    }

    @Test
    void process_whenJobAlreadyCompleted_shouldDoNothing() {
        UUID jobId = UUID.randomUUID();
        SignatureJob job = buildPendingJob(jobId);
        job.complete("/path/signed.xml", "signed.xml");

        when(jobRepository.findById(jobId)).thenReturn(Optional.of(job));

        orchestrator.process("code", jobId);

        verifyNoInteractions(oAuthService);
    }

    @Test
    void process_whenTokenExchangeFails_shouldMarkJobAsFailed() {
        UUID jobId = UUID.randomUUID();
        SignatureJob job = buildPendingJob(jobId);

        when(jobRepository.findById(jobId)).thenReturn(Optional.of(job));
        when(oAuthService.exchangeCodeForToken(anyString()))
                .thenThrow(new NeoIdApiException("Token inválido"));

        assertThrows(NeoIdApiException.class,
                () -> orchestrator.process("bad-code", jobId));

        assertEquals(JobStatus.FAILED, job.getStatus());
        assertNotNull(job.getErrorMessage());
    }

    @Test
    void process_whenSignatureFails_shouldMarkJobAsFailed() {
        UUID jobId = UUID.randomUUID();
        SignatureJob job = buildPendingJob(jobId);

        when(jobRepository.findById(jobId)).thenReturn(Optional.of(job));
        when(oAuthService.exchangeCodeForToken(anyString()))
                .thenReturn(new NeoIdTokenResponse("token", "Bearer", 3600, "signature"));
        when(oAuthService.sendHashForSignature(anyString(), any()))
                .thenThrow(new NeoIdApiException("Falha na assinatura remota"));

        assertThrows(NeoIdApiException.class,
                () -> orchestrator.process("code", jobId));

        assertEquals(JobStatus.FAILED, job.getStatus());
    }
}
