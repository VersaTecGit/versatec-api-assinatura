package com.versatec.signature.strategy;

import com.versatec.customs.FileLocationEnum;
import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureJob;
import com.versatec.domain.SignatureType;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.neoid.NeoIdOAuthService;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NeoIdSignatureStrategyTest {

    @Mock
    private NeoIdOAuthService oAuthService;

    @Mock
    private SignatureJobRepository jobRepository;

    private NeoIdSignatureStrategy strategy;
    private FileUtils fileUtils;
    private Path xmlFilePath;

    @BeforeEach
    void setUp() throws Exception {
        strategy = new NeoIdSignatureStrategy(oAuthService, jobRepository);
        fileUtils = new FileUtils(FileStoragePropertiesMock.create());
        xmlFilePath = fileUtils.getFilePath("test.xml", FileLocationEnum.ASSET);
        Files.write(xmlFilePath, "<root/>".getBytes(StandardCharsets.UTF_8));
    }

    @AfterEach
    void tearDown() throws IOException {
        fileUtils.removeFile(xmlFilePath);
    }

    @Test
    void signXml_shouldCalculateHashAndPersistJobAndReturnPending() throws Exception {
        String expectedAuthUrl = "https://neoid.serpro.gov.br/oauth?state=test";
        when(oAuthService.buildAuthorizationUrl(any(UUID.class))).thenReturn(expectedAuthUrl);

        var command = new SignXmlCommand(xmlFilePath, "test.xml",
                null, false, null, "user-123", null, null);

        SignatureResult result = strategy.signXml(command);

        // Verifica tipo de retorno
        assertInstanceOf(SignatureResult.Pending.class, result);
        SignatureResult.Pending pending = (SignatureResult.Pending) result;
        assertNotNull(pending.jobId());
        assertEquals(expectedAuthUrl, pending.authorizationUrl());

        // Verifica que o job foi salvo
        ArgumentCaptor<SignatureJob> jobCaptor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository).save(jobCaptor.capture());

        SignatureJob savedJob = jobCaptor.getValue();
        assertEquals(JobStatus.PENDING, savedJob.getStatus());
        assertEquals("test.xml", savedJob.getOriginalFileName());
        assertEquals("user-123", savedJob.getUserId());
        assertNotNull(savedJob.getDocumentHash());
        assertNotNull(savedJob.getExpiresAt());
    }

    @Test
    void signXml_hashShouldBeDeterministic() throws Exception {
        when(oAuthService.buildAuthorizationUrl(any())).thenReturn("http://auth.url");

        var command = new SignXmlCommand(xmlFilePath, "test.xml",
                null, false, null, null, null, null);

        strategy.signXml(command);
        strategy.signXml(command);

        // Ambas as chamadas devem salvar o mesmo hash (SHA-256 é determinístico)
        ArgumentCaptor<SignatureJob> captor = ArgumentCaptor.forClass(SignatureJob.class);
        verify(jobRepository, times(2)).save(captor.capture());

        String hash1 = captor.getAllValues().get(0).getDocumentHash();
        String hash2 = captor.getAllValues().get(1).getDocumentHash();
        assertEquals(hash1, hash2);
    }

    @Test
    void supports_shouldReturnNEOID() {
        assertEquals(SignatureType.NEOID, strategy.supports());
    }
}
