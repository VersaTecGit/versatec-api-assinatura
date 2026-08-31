package com.versatec.safeid;

import com.versatec.customs.FileLocationEnum;
import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.safeid.dto.SafeIdSignatureResponse;
import com.versatec.safeid.dto.SafeIdTokenResponse;
import com.versatec.signature.orchestrator.SafeIdCallbackOrchestrator;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Testes unitários para {@link SafeIdCallbackOrchestrator}.
 * <p>
 * Toda comunicação com a API SafeID é substituída por mocks do Mockito,
 * permitindo validar toda a lógica do orquestrador sem dependência de rede
 * ou certificado real.
 */
@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class SafeIdCallbackOrchestratorTest {

    @Mock
    private SafeIdOAuthService oAuthService;

    @Mock
    private SafeIdWebhookService webhookService;

    @Mock
    private SignatureJobRepository jobRepository;

    private SafeIdCallbackOrchestrator orchestrator;
    private FileUtils fileUtils;
    private Path xmlFilePath;

    // Dados de teste reutilizados
    private UUID jobId;
    private String codeVerifier;
    private String documentHashBase64;
    private SignatureJob pendingJob;

    @BeforeEach
    void setUp() throws Exception {
        fileUtils = new FileUtils(FileStoragePropertiesMock.create());
        orchestrator = spy(new SafeIdCallbackOrchestrator(oAuthService, webhookService, jobRepository, fileUtils));

        // Prepara um arquivo XML de teste
        jobId = UUID.randomUUID();
        codeVerifier = "test-code-verifier-com-tamanho-suficiente-para-pkce-rfc7636";
        byte[] content = "<root><data>conteudo de teste</data></root>".getBytes();
        byte[] hashBytes = MessageDigest.getInstance("SHA-256").digest(content);
        documentHashBase64 = Base64.getEncoder().encodeToString(hashBytes);

        // Cria o arquivo físico temporário (simulando o arquivo salvo pela strategy)
        xmlFilePath = fileUtils.getFilePath("test-" + jobId + ".xml", FileLocationEnum.UPLOAD);
        Files.write(xmlFilePath, content);

        // Monta o SignatureJob PENDING que seria recuperado do banco
        pendingJob = SignatureJob.builder()
                .id(jobId)
                .userId("user-teste")
                .documentHash(documentHashBase64)
                .originalFilePath(xmlFilePath.toString())
                .originalFileName("contrato.xml")
                .codeVerifier(codeVerifier)
                .build();
                
        org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner mockedSigner = mock(org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner.class);
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        org.w3c.dom.Document doc = factory.newDocumentBuilder().newDocument();
        org.w3c.dom.Element root = doc.createElement("dummy-xml");
        doc.appendChild(root);
        lenient().when(mockedSigner.signEnveloped(any(byte[].class))).thenReturn(doc);
        lenient().doReturn(mockedSigner).when(orchestrator).createXmlSigner();
        
        // Retorna certificado base64 dummy para todos os testes que acionam getCertificateInfo
        lenient().when(oAuthService.getCertificateInfo(any())).thenReturn(getDummyCertificate());
    }

    @AfterEach
    void tearDown() throws IOException {
        fileUtils.removeFile(xmlFilePath);
        // Remove o arquivo assinado gerado pelo orquestrador (se criado)
        Path signedFile = fileUtils.getFilePath("contrato_assinado.xml", FileLocationEnum.DOWNLOAD);
        fileUtils.removeFile(signedFile);
    }

    // -------------------------------------------------------------------------
    // Cenário 1: Fluxo feliz — callback processado com sucesso
    // -------------------------------------------------------------------------

    @Test
    void process_shouldExchangeCodeForTokenAndPrepareSigner() throws Exception {
        // Arrange
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));
        SafeIdTokenResponse tokenResponse = mockTokenResponse();
        when(oAuthService.exchangeCodeForToken("auth-code-123", codeVerifier))
                .thenReturn(tokenResponse);

        // Act
        orchestrator.process("auth-code-123", jobId);

        // Assert
        verify(oAuthService).exchangeCodeForToken("auth-code-123", codeVerifier);
    }

    @Test
    void process_shouldUpdateJobStatusToCompleted() throws Exception {
        // Arrange
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        orchestrator.process("auth-code-123", jobId);

        // Assert
        ArgumentCaptor<SignatureJob> jobCaptor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(jobCaptor.capture());
        assertEquals(JobStatus.COMPLETED, jobCaptor.getValue().getStatus());
        assertNotNull(jobCaptor.getValue().getSignedFilePath());
        assertNotNull(jobCaptor.getValue().getCompletedAt());
    }

    @Test
    void process_shouldSaveSignedFileWithCorrectNaming() throws Exception {
        // Arrange
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        orchestrator.process("auth-code-123", jobId);

        // Assert: arquivo assinado deve ter o sufixo "_assinado"
        ArgumentCaptor<SignatureJob> jobCaptor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(jobCaptor.capture());
        assertEquals("contrato_assinado.xml", jobCaptor.getValue().getSignedFileName());
    }

    @Test
    void process_shouldReturnNullReturnUrlWhenNotConfigured() throws Exception {
        // Arrange — job sem returnUrl
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        String returnUrl = orchestrator.process("auth-code-123", jobId);

        // Assert
        assertNull(returnUrl, "returnUrl deve ser null quando não configurada no job");
    }

    @Test
    void process_shouldReturnConfiguredReturnUrl() throws Exception {
        // Arrange — job com returnUrl configurada
        SignatureJob jobComReturnUrl = SignatureJob.builder()
                .id(jobId).userId("user").documentHash(documentHashBase64)
                .originalFilePath(xmlFilePath.toString()).originalFileName("contrato.xml")
                .codeVerifier(codeVerifier).returnUrl("https://minha-app.com/sucesso")
                .build();
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(jobComReturnUrl));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        String returnUrl = orchestrator.process("auth-code-123", jobId);

        // Assert
        assertEquals("https://minha-app.com/sucesso", returnUrl);
    }

    // -------------------------------------------------------------------------
    // Cenário 2: Webhook assíncrono
    // -------------------------------------------------------------------------

    @Test
    void process_shouldFireWebhookOnSuccessWhenConfigured() throws Exception {
        // Arrange — job com webhookUrl configurada
        SignatureJob jobComWebhook = SignatureJob.builder()
                .id(jobId).userId("user").documentHash(documentHashBase64)
                .originalFilePath(xmlFilePath.toString()).originalFileName("contrato.xml")
                .codeVerifier(codeVerifier).webhookUrl("https://minha-app.com/webhook")
                .build();
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(jobComWebhook));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        orchestrator.process("auth-code-123", jobId);

        // Assert
        verify(webhookService).notifyWebhook(
                eq("https://minha-app.com/webhook"),
                eq(jobId),
                eq(JobStatus.COMPLETED),
                isNull()
        );
    }

    @Test
    void process_shouldNotFireWebhookWhenNotConfigured() throws Exception {
        // Arrange — job sem webhookUrl
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));
        when(oAuthService.exchangeCodeForToken(any(), any())).thenReturn(mockTokenResponse());
        when(oAuthService.sendHashForSignature(any(), any(), any())).thenReturn(mockSignatureResponse());

        // Act
        orchestrator.process("auth-code-123", jobId);

        // Assert
        verifyNoInteractions(webhookService);
    }

    // -------------------------------------------------------------------------
    // Cenário 3: Casos de erro e borda
    // -------------------------------------------------------------------------

    @Test
    void process_shouldThrowWhenJobNotFound() {
        when(jobRepository.findById(jobId)).thenReturn(Optional.empty());

        assertThrows(SafeIdApiException.class,
                () -> orchestrator.process("auth-code-123", jobId),
                "Deve lançar exceção quando o job não existir no banco");
    }

    @Test
    void process_shouldIgnoreCallbackWhenJobAlreadyCompleted() throws Exception {
        // Simula um job já COMPLETED (duplo callback, retry, etc.)
        pendingJob.complete("path/assinado.xml", "assinado.xml");
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(pendingJob));

        // Act — não deve lançar exceção, deve ignorar silenciosamente
        orchestrator.process("auth-code-123", jobId);

        // Assert — nenhuma chamada ao SafeID deve ter ocorrido
        verifyNoInteractions(oAuthService);
    }

    @Test
    void process_shouldFailJobWhenCodeVerifierIsMissing() {
        // Job sem code_verifier (cenário impossível em produção, mas testamos a defesa)
        SignatureJob jobSemVerifier = SignatureJob.builder()
                .id(jobId).userId("user").documentHash(documentHashBase64)
                .originalFilePath(xmlFilePath.toString()).originalFileName("contrato.xml")
                .build(); // codeVerifier não definido
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(jobSemVerifier));

        // Act + Assert — deve processar sem lançar exceção mas marcar o job como FAILED
        orchestrator.process("auth-code-123", jobId);

        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());
        assertEquals(JobStatus.FAILED, captor.getValue().getStatus());
        verifyNoInteractions(oAuthService);
    }

    @Test
    void process_shouldFailJobAndFireWebhookOnSafeIdApiException() {
        // Arrange
        SignatureJob jobComWebhook = SignatureJob.builder()
                .id(jobId).userId("user").documentHash(documentHashBase64)
                .originalFilePath(xmlFilePath.toString()).originalFileName("contrato.xml")
                .codeVerifier(codeVerifier).webhookUrl("https://minha-app.com/webhook")
                .build();
        when(jobRepository.findById(jobId)).thenReturn(Optional.of(jobComWebhook));
        when(oAuthService.exchangeCodeForToken(any(), any()))
                .thenThrow(new SafeIdApiException("Token inválido [401]"));

        // Act
        assertThrows(SafeIdApiException.class,
                () -> orchestrator.process("auth-code-123", jobId));

        // Assert — job deve ser marcado como FAILED
        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(captor.capture());
        assertEquals(JobStatus.FAILED, captor.getValue().getStatus());

        // Webhook deve ser disparado com status FAILED
        verify(webhookService).notifyWebhook(
                eq("https://minha-app.com/webhook"),
                eq(jobId),
                eq(JobStatus.FAILED),
                anyString()
        );
    }

    // -------------------------------------------------------------------------
    // Helpers de montagem de mocks
    // -------------------------------------------------------------------------

    private SafeIdTokenResponse mockTokenResponse() {
        return new SafeIdTokenResponse(
                "access-token-mock", "Bearer", 300,
                "signature_session", "CPF", "123.456.789-00"
        );
    }

    private SafeIdSignatureResponse mockSignatureResponse() {
        // Monta uma assinatura fake em Base64 (simula a resposta do PSC)
        String fakeSignatureBase64 = Base64.getEncoder()
                .encodeToString("<FakeSignature>assinatura-cms-mock</FakeSignature>".getBytes());

        SafeIdSignatureResponse.SignatureItem item = new SafeIdSignatureResponse.SignatureItem(
                jobId.toString(),
                fakeSignatureBase64
        );
        return new SafeIdSignatureResponse("alias-certificado-mock", List.of(item));
    }

    private String getDummyCertificate() {
        return "MIIC/zCCAeegAwIBAgIUQ3QrFkJJrL3bmbP9zLi/OMJu8G0wDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEVGVzdDAeFw0yNjA4MjcxODMwMDRaFw0yNzA4MjcxODMwMDRaMA8xDTALBgNVBAMMBFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD4yUxK5LNlzS7cKsdR5ne9iYB8gmeuBZuQIGzNbH0svK3hHYWFrOgRl2ii8f2jDTvLgOx4PE0Eb2SBvxs3VoyZVn5QwVkUeze4U9cNJiftV7F6/vdG3TdBtsIRhssNwhL+VxL/7bnD+fqGqaSIOFX/X5T2tP1XLd3K/5U0vvXk2zgh7dFzaPayfIqdgYhVQi89/2jRT1CWRxW25mKpmdcuxrF7ihiqrbyNRTmqJsRyyYV5D+8rto75pTBTOcyG43BJkZC+cqg+8humkBHbspcxjAHX0MoIUZoPMMU1CJG/aOsq0LFiJvQ4xFHuF+30DxiyjBrWBqyGSYKLW3g8xgH7AgMBAAGjUzBRMB0GA1UdDgQWBBTWnXTvBGedLTqEssyFmt/eQCiGBDAfBgNVHSMEGDAWgBTWnXTvBGedLTqEssyFmt/eQCiGBDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB0Kbw3gsmXi7vboF9SxGGrLg1VEbVzocjyDMTNQQ6n4dXU7zwbRPaRkow/V+diZIIq+d6U+podp4UeUhZUWTn8MqrtLoN4t0+O3+BodHIK5HEhMk1G8y9cP8FFSR8EU71eJAHIgxCxxPduRCWURMlJgStqCk9oHRCT3bXxsQ6AHxEK/focWvl/avO9Q0ptPc8cKzH8i8yLPBCC9/fm4zsPOYNhEXOiZhNH7nawYWPl1lKHCnq787MkiHmFeXw6iRAsxTpTygAFXFVgRH1l2rRysTzv3VrYmqAZaRuS1feJeHk2D+HWumHWTuujrqByKpovpJQCf5TE8NRKRfaVZ1/S";
    }
}
