package com.versatec.services;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.utils.FileUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.jupiter.api.*;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SignatureServiceTest {

    private FileUtils fileUtils;

    @InjectMocks
    private SignatureService signatureService;

    @Mock
    private CustomCertificate customCertificate;

    private Path BLANK_PDF;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        this.fileUtils = new FileUtils(FileStoragePropertiesMock.create());

        this.signatureService = spy(new SignatureService());

        var certificatePath =  fileUtils.getFilePath("testCert.pfx", FileLocationEnum.ASSET);
        customCertificate = new CustomCertificate(certificatePath, "123456");

        //Create blank PDF
        var fileName = "test.pdf";
        BLANK_PDF = this.fileUtils.getFilePath(fileName, FileLocationEnum.ASSET);
        File file = BLANK_PDF.toFile();
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage());
            doc.save(file);
        }
    }

    @Test
    void testSignDocument_shouldReturnSignature() throws Exception {
        // Arrange
        var content = Files.readAllBytes(BLANK_PDF);

        var mockSigner = mock(PKCS7Signer.class);
        var mockReturn = "signed content".getBytes();
        doReturn(mockSigner).when(signatureService).getPKCS7Signer(customCertificate);
        when(mockSigner.doAttachedSign(content)).thenReturn(mockReturn);

        // Act
        byte[] result = signatureService.signDocument(BLANK_PDF, customCertificate);

        // Assert
        assertArrayEquals(mockReturn, result);
        verify(mockSigner).doAttachedSign(content); // Verify the interaction with mockSigner
    }

    @AfterAll
    void tearDown() throws IOException {
        this.fileUtils.removeFile(BLANK_PDF);
    }
}
