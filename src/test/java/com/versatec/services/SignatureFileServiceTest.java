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
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SignatureFileServiceTest {

    private FileUtils fileUtils;

    @InjectMocks
    @Spy
    private SignatureFileService signatureFileService;

    @Mock
    private CustomCertificate customCertificate;

    private Path BLANK_PDF;
    private Path SIGNED_PDF;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        this.fileUtils = new FileUtils(FileStoragePropertiesMock.create());

        var signatureImageGenerator = new SignatureImageGenerator(fileUtils, AppPropertiesMock.create());
        this.signatureFileService = spy(new SignatureFileService(signatureImageGenerator, fileUtils));

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
        var signedFileName = SignatureFileService.addSignatureName(fileName);
        SIGNED_PDF = this.fileUtils.getFilePath(signedFileName, FileLocationEnum.DOWNLOAD);
    }

    @Test
    void testCreatePDF_WithQRAndDefaultPosition_shouldReturnSignedPDF() throws Exception {
        // Arrange
        byte[] signedDocument = "signed content".getBytes();

        // Act
        Path result = signatureFileService.createPDF(
                BLANK_PDF,
                signedDocument,
                customCertificate,
                new VisualSignatureConfig(null, null, null, null ),
                "http://example.com"
        );

        // Assert
        assertNotNull(result);
        assertTrue(Files.exists(result));
    }

    @Test
    void testCreatePDF_WithoutQRAndCustomPosition_shouldReturnSignedPDF() throws Exception {
        // Arrange
        byte[] signedDocument = "signed content".getBytes();

        // Act
        Path result = signatureFileService.createPDF(
                BLANK_PDF,
                signedDocument,
                customCertificate,
                new VisualSignatureConfig(0, 10, 10, false),
                ""
        );

        // Assert
        assertNotNull(result);
        assertTrue(Files.exists(result));
    }

    @AfterAll
    void tearDown() throws IOException {
        this.fileUtils.removeFile(BLANK_PDF);
        this.fileUtils.removeFile(SIGNED_PDF);
    }
}
