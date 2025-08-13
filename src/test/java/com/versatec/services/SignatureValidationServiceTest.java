package com.versatec.services;

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
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SignatureValidationServiceTest {

    private FileUtils fileUtils;

    @InjectMocks
    @Spy
    private SignatureValidationService signatureValidationService;

    @Mock
    private CustomCertificate customCertificate;

    private Path BLANK_PDF;
    private Path SIGNED_PDF;

    @Mock
    private CAdESChecker cadesChecker;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        this.fileUtils = new FileUtils(FileStoragePropertiesMock.create());

        this.signatureValidationService = spy(new SignatureValidationService());

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
        var signatureImageGenerator = new SignatureImageGenerator(fileUtils, AppPropertiesMock.create());
        var signatureFileService = new SignatureFileService(signatureImageGenerator, fileUtils);
        SIGNED_PDF = signatureFileService.createPDF(
                BLANK_PDF,
                "signed content".getBytes(),
                customCertificate,
                new VisualSignatureConfig(null, null, null, null ),
                "http://example.com"
        );
    }

    @Test
    void testValidateAllSignatures_WithSignatureInformations() throws Exception {
        //Arrange
        List<SignatureInformations> mockReturn = new ArrayList<>();
        mockReturn.add(new SignatureInformations());
        when(cadesChecker.checkAttachedSignature(any())).thenReturn(mockReturn);
        when(cadesChecker.getSignaturesInfo()).thenReturn(mockReturn);
        doReturn(cadesChecker).when(signatureValidationService).getCAdESChecker();

        // Act
        List<SignatureInformations> results = signatureValidationService.validateAllSignatures(SIGNED_PDF);

        // Assert
        assertEquals(mockReturn, results);
        assertNotNull(results);
        assertFalse(results.isEmpty());
        verify(cadesChecker).checkAttachedSignature(any(byte[].class));
    }

    @Test
    void testValidateAllSignatures_WithoutSignatureInformations() throws Exception {
        //Arrange
        List<SignatureInformations> mockReturn = new ArrayList<>();
        when(cadesChecker.checkAttachedSignature(any())).thenReturn(mockReturn);
        doReturn(cadesChecker).when(signatureValidationService).getCAdESChecker();

        // Act
        List<SignatureInformations> results = signatureValidationService.validateAllSignatures(SIGNED_PDF);

        // Assert
        assertEquals(mockReturn, results);
        assertTrue(results.isEmpty());
        verify(cadesChecker).checkAttachedSignature(any(byte[].class));
    }

    @AfterAll
    void tearDown() throws IOException {
        this.fileUtils.removeFile(BLANK_PDF);
        this.fileUtils.removeFile(SIGNED_PDF);
    }
}
