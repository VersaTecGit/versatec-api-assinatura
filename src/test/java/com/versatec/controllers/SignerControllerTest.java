package com.versatec.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.versatec.customs.XmlNodeNotFoundException;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.services.SignatureFileService;
import com.versatec.services.SignatureService;
import com.versatec.services.SignatureValidationService;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.signature.orchestrator.NeoIdCallbackOrchestrator;
import com.versatec.signature.orchestrator.SafeIdCallbackOrchestrator;
import com.versatec.signature.resolver.SignatureStrategyResolver;
import com.versatec.signature.strategy.SignatureStrategy;
import com.versatec.utils.FileUtils;
import com.versatec.utils.XmlNodeLocator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SignerControllerTest {

    @Mock
    private SignatureService signatureService;
    @Mock
    private SignatureFileService signatureFileService;
    @Mock
    private SignatureValidationService signatureValidationService;
    @Mock
    private FileUtils fileUtils;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private SignatureStrategyResolver signatureStrategyResolver;
    @Mock
    private NeoIdCallbackOrchestrator neoIdCallbackOrchestrator;
    @Mock
    private SafeIdCallbackOrchestrator safeIdCallbackOrchestrator;
    @Mock
    private SignatureJobRepository signatureJobRepository;
    @Mock
    private XmlNodeLocator xmlNodeLocator;

    @InjectMocks
    private SignerController signerController;

    private MockMultipartFile xmlFile;

    @BeforeEach
    void setUp() throws Exception {
        xmlFile = new MockMultipartFile("file", "test.xml", "application/xml", "<root></root>".getBytes());
    }

    @Test
    void signXml_withInvalidTargetXPath_shouldReturn400() throws Exception {
        // Arrange
        Path mockPath = java.nio.file.Files.createTempFile("test", ".xml");
        java.nio.file.Files.write(mockPath, "<root></root>".getBytes());
        when(fileUtils.uploadFile(any(), any())).thenReturn(mockPath);
        when(xmlNodeLocator.locate(any(), eq("//Invalid"))).thenThrow(new XmlNodeNotFoundException("//Invalid"));

        // Act
        ResponseEntity<?> response = signerController.signXml(
                xmlFile, null, null, com.versatec.domain.SignatureType.SAFEID, false,
                "//Invalid", "user-1", null, null
        );

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("XML node not found for XPath expression: '//Invalid'", response.getBody());
        
        // Verify strategy was never called
        verify(signatureStrategyResolver, never()).resolve(any());
    }
}
