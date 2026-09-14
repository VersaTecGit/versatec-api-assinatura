package com.versatec.services;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.utils.FileUtils;
import com.versatec.utils.XmlNodeLocator;
import com.versatec.utils.XmlNodeSigner;
import com.versatec.utils.XmlSignatureRelocator;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner;
import org.junit.jupiter.api.*;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
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

        this.signatureService = spy(new SignatureService(
                new TimeStampService(),
                new XmlNodeSigner(),
                new XmlSignatureRelocator(new XmlNodeLocator())));

        var certificatePath = fileUtils.getFilePath("testCert.pfx", FileLocationEnum.ASSET);
        customCertificate = new CustomCertificate(certificatePath, "123456");

        // Create blank PDF
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

    @Test
    void testConstructor_WithOnlyTimeStampService_shouldInitializeAllFields() {
        var service = new SignatureService(
                new TimeStampService(),
                new XmlNodeSigner(),
                new XmlSignatureRelocator(new XmlNodeLocator()));
        assertNotNull(service);
    }

    @Test
    void testConstructor_WithAllParameters_shouldInitializeAllFields() {
        var mockTimeStampService = mock(TimeStampService.class);
        var mockXmlNodeSigner = mock(XmlNodeSigner.class);
        var mockXmlSignatureRelocator = mock(XmlSignatureRelocator.class);

        var service = new SignatureService(mockTimeStampService, mockXmlNodeSigner, mockXmlSignatureRelocator);
        assertNotNull(service);
    }

    @Test
    void testSignXmlDocument_withoutTargetXPath_shouldUseXmlSigner() throws Exception {
        // Arrange
        var mockXmlSigner = mock(XMLSigner.class);
        var testDoc = createTestDocument();

        doReturn(mockXmlSigner).when(signatureService).getXmlSigner(any(), anyBoolean());
        when(mockXmlSigner.signEnveloped(anyBoolean(), anyString())).thenReturn(testDoc);

        // Act
        byte[] result = signatureService.signXmlDocument(BLANK_PDF, customCertificate, false, null);

        // Assert
        assertNotNull(result);
        verify(mockXmlSigner).signEnveloped(true, BLANK_PDF.toString());
    }

    @Test
    void testSignXmlDocument_withoutTargetXPath_usingDefaultConstructor() throws Exception {
        // Arrange
        var service = spy(new SignatureService(
                new TimeStampService(),
                new XmlNodeSigner(),
                new XmlSignatureRelocator(new XmlNodeLocator())));
        var mockXmlSigner = mock(XMLSigner.class);
        var testDoc = createTestDocument();

        doReturn(mockXmlSigner).when(service).getXmlSigner(any(), anyBoolean());
        when(mockXmlSigner.signEnveloped(anyBoolean(), anyString())).thenReturn(testDoc);

        // Act
        byte[] result = service.signXmlDocument(BLANK_PDF, customCertificate, false, null);

        // Assert
        assertNotNull(result);
        verify(mockXmlSigner).signEnveloped(true, BLANK_PDF.toString());
    }

    @Test
    void testSignXmlDocument_withTargetXPath_shouldLocateAndMoveSignature() throws Exception {
        // Arrange
        var mockTimeStampService = mock(TimeStampService.class);
        var mockXmlNodeSigner = mock(XmlNodeSigner.class);
        var mockXmlSignatureRelocator = mock(XmlSignatureRelocator.class);

        var service = spy(new SignatureService(mockTimeStampService, mockXmlNodeSigner, mockXmlSignatureRelocator));

        var mockXmlSigner = mock(XMLSigner.class);
        var testDoc = createTestDocument();

        doReturn(mockXmlSigner).when(service).getXmlSigner(any(), anyBoolean());
        when(mockXmlSigner.signEnveloped(anyBoolean(), anyString())).thenReturn(testDoc);

        // Act
        byte[] result = service.signXmlDocument(BLANK_PDF, customCertificate, false, "targetNode");

        // Assert
        assertNotNull(result);
        verify(mockXmlSigner).signEnveloped(true, BLANK_PDF.toString());
        verify(mockXmlSignatureRelocator).relocate(testDoc, "targetNode");
    }

    private Document createTestDocument() throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        var builder = factory.newDocumentBuilder();
        var doc = builder.newDocument();
        var root = doc.createElement("root");
        doc.appendChild(root);

        var target = doc.createElement("targetNode");
        root.appendChild(target);

        // Simulating the Signature element appended by Demoiselle
        var signature = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        root.appendChild(signature);

        return doc;
    }

    @AfterAll
    void tearDown() throws IOException {
        this.fileUtils.removeFile(BLANK_PDF);
    }
}
