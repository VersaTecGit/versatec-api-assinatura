package com.versatec.signature.strategy;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.FileLocationEnum;
import com.versatec.mocks.FileStoragePropertiesMock;
import com.versatec.services.SignatureService;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.utils.FileUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class A1SignatureStrategyTest {

    @Mock
    private SignatureService signatureService;

    @Mock
    private CustomCertificate customCertificate;

    private A1SignatureStrategy strategy;
    private FileUtils fileUtils;
    private Path dummyFilePath;

    @BeforeEach
    void setUp() throws Exception {
        strategy = new A1SignatureStrategy(signatureService);
        fileUtils = new FileUtils(FileStoragePropertiesMock.create());
        dummyFilePath = fileUtils.getFilePath("dummy.xml", FileLocationEnum.ASSET);
        dummyFilePath.toFile().createNewFile();
    }

    @AfterEach
    void tearDown() throws IOException {
        fileUtils.removeFile(dummyFilePath);
    }

    @Test
    void signXml_shouldDelegateToSignatureServiceAndReturnCompleted() throws Exception {
        byte[] expectedBytes = "<signed/>".getBytes();
        when(signatureService.signXmlDocument(any(), any(), anyBoolean(), any()))
                .thenReturn(expectedBytes);

        var command = new SignXmlCommand(dummyFilePath, "doc.xml",
                customCertificate, false, null, null, null, null);

        SignatureResult result = strategy.signXml(command);

        assertInstanceOf(SignatureResult.Completed.class, result);
        SignatureResult.Completed completed = (SignatureResult.Completed) result;
        assertArrayEquals(expectedBytes, completed.document());
        assertEquals("doc.xml", completed.fileName());
    }

    @Test
    void signXml_shouldPassTimeStampAndXPathToService() throws Exception {
        when(signatureService.signXmlDocument(any(), any(), anyBoolean(), any()))
                .thenReturn(new byte[] {});

        var command = new SignXmlCommand(dummyFilePath, "doc.xml",
                customCertificate, true, "/root/node", null, null, null);

        strategy.signXml(command);

        verify(signatureService).signXmlDocument(dummyFilePath, customCertificate, true, "/root/node");
    }

    @Test
    void supports_shouldReturnA1() {
        assertEquals(com.versatec.domain.SignatureType.A1, strategy.supports());
    }
}
