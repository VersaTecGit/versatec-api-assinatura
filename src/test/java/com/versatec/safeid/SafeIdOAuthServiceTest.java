package com.versatec.safeid;

import com.versatec.config.SafeIdProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes unitários para {@link SafeIdOAuthService#buildAuthorizationUrl}.
 * <p>
 * Apenas o método de construção da URL é testado aqui sem dependência de rede,
 * pois os métodos de troca de token e envio de hash dependem do RestTemplate
 * e são validados indiretamente pelo {@link SafeIdCallbackOrchestratorTest}.
 */
@ExtendWith(MockitoExtension.class)
class SafeIdOAuthServiceTest {

    @Mock
    private SafeIdProperties properties;

    private SafeIdOAuthService oAuthService;

    @BeforeEach
    void setUp() {
        // Configuração mínima para os testes de buildAuthorizationUrl
        org.mockito.Mockito.when(properties.getAuthorizationEndpoint())
                .thenReturn("https://pscsafeweb.safewebpss.com.br/Service/Microservice/OAuth/api/v0/oauth/authorize");
        org.mockito.Mockito.when(properties.getClientId())
                .thenReturn("meu-client-id-test");
        org.mockito.Mockito.when(properties.getCallbackUrl())
                .thenReturn("http://localhost:8080/api/v1/safeid/callback");

        oAuthService = new SafeIdOAuthService(properties,
                new org.springframework.web.client.RestTemplate());
    }

    @Test
    void buildAuthorizationUrl_shouldContainResponseTypeCode() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "qualquerChallenge");

        assertTrue(url.contains("response_type=code"),
                "URL deve conter response_type=code");
    }

    @Test
    void buildAuthorizationUrl_shouldContainClientId() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "qualquerChallenge");

        assertTrue(url.contains("client_id=meu-client-id-test"),
                "URL deve conter o client_id correto");
    }

    @Test
    void buildAuthorizationUrl_shouldContainRedirectUri() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "qualquerChallenge");

        assertTrue(url.contains("redirect_uri="),
                "URL deve conter redirect_uri");
        assertTrue(url.contains("safeid%2Fcallback") || url.contains("safeid/callback"),
                "URL deve conter o path do callback");
    }

    @Test
    void buildAuthorizationUrl_shouldContainStateAsJobId() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "qualquerChallenge");

        assertTrue(url.contains("state=" + jobId),
                "URL deve conter state igual ao jobId");
    }

    @Test
    void buildAuthorizationUrl_shouldContainPkceParameters() {
        UUID jobId = UUID.randomUUID();
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        String url = oAuthService.buildAuthorizationUrl(jobId, challenge);

        assertTrue(url.contains("code_challenge=" + challenge),
                "URL deve conter o code_challenge correto");
        assertTrue(url.contains("code_challenge_method=S256"),
                "URL deve especificar o método S256");
    }

    @Test
    void buildAuthorizationUrl_shouldContainSignatureScope() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "challenge");

        assertTrue(url.contains("scope=signature_session"),
                "URL deve conter o scope 'signature_session'");
    }

    @Test
    void buildAuthorizationUrl_shouldPointToConfiguredEndpoint() {
        UUID jobId = UUID.randomUUID();
        String url = oAuthService.buildAuthorizationUrl(jobId, "challenge");

        assertTrue(url.startsWith("https://pscsafeweb.safewebpss.com.br"),
                "URL deve iniciar com o endpoint configurado nas properties");
    }
}
