package com.versatec.services;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.customs.VisualSignatureConfig;
import com.versatec.mocks.AppPropertiesMock;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.utils.FileUtils;
import com.versatec.utils.SignatureImageGenerator;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.junit.jupiter.api.*;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SignatureServiceTest {

    private FileUtils fileUtils;

    @InjectMocks
    @Spy
    private SignatureService signatureService;

    @Mock
    private CustomCertificate customCertificate;

    private Path BLANK_PDF;
    private Path SIGNED_PDF;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        this.fileUtils = new FileUtils(FileStoragePropertiesMock.create());

        var signatureImageGenerator = new SignatureImageGenerator(fileUtils, AppPropertiesMock.create());
        this.signatureService = spy(new SignatureService(fileUtils, signatureImageGenerator));

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

        //Register signed Path
        var signedFileName = SignatureService.addSignatureName(fileName);
        SIGNED_PDF = this.fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);
    }

    @Test
    @Order(0)
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

    @Test
    @Order(1)
    void testCreatePDF_WithQRAndDefaultPosition_shouldReturnSignedPDF() throws Exception {
        // Arrange
        byte[] signedDocument = "signed content".getBytes();

        // Act
        Path result = signatureService.createPDF(
                BLANK_PDF,
                signedDocument,
                customCertificate,
                null,
                "http://example.com"
        );

        // Assert
        assertNotNull(result);
        assertTrue(Files.exists(result));
    }

    @Test
    @Order(1)
    void testCreatePDF_WithoutQRAndCustomPosition_shouldReturnSignedPDF() throws Exception {
        // Arrange
        byte[] signedDocument = "signed content".getBytes();

        // Act
        Path result = signatureService.createPDF(
                BLANK_PDF,
                signedDocument,
                customCertificate,
                new VisualSignatureConfig(0, 10, 10),
                ""
        );

        // Assert
        assertNotNull(result);
        assertTrue(Files.exists(result));
    }

    @Mock
    private CAdESChecker cadesChecker;

    @Test
    @Order(2)
    void testValidateAllSignatures_WithSignatureInformations() throws Exception {
        //Arrange
        List<SignatureInformations> mockReturn = new ArrayList<>();
        mockReturn.add(new SignatureInformations());
        when(cadesChecker.checkAttachedSignature(any())).thenReturn(mockReturn);
        when(cadesChecker.getSignaturesInfo()).thenReturn(mockReturn);
        doReturn(cadesChecker).when(signatureService).getCAdESChecker();

        // Act
        List<SignatureInformations> results = signatureService.validateAllSignatures(SIGNED_PDF);

        // Assert
        assertEquals(mockReturn, results);
        assertNotNull(results);
        assertFalse(results.isEmpty());
        verify(cadesChecker).checkAttachedSignature(any(byte[].class));
    }

    @Test
    @Order(2)
    void testValidateAllSignatures_WithoutSignatureInformations() throws Exception {
        //Arrange
        List<SignatureInformations> mockReturn = new ArrayList<>();
        when(cadesChecker.checkAttachedSignature(any())).thenReturn(mockReturn);
        doReturn(cadesChecker).when(signatureService).getCAdESChecker();

        // Act
        List<SignatureInformations> results = signatureService.validateAllSignatures(SIGNED_PDF);

        // Assert
        assertEquals(mockReturn, results);
        assertTrue(results.isEmpty());
        verify(cadesChecker).checkAttachedSignature(any(byte[].class));
    }

    @AfterAll
    public void tearDown() throws IOException {
        this.fileUtils.removeFile(BLANK_PDF);
        this.fileUtils.removeFile(SIGNED_PDF);
    }
}
