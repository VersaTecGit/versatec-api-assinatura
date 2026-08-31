package com.versatec.neoid;

import com.versatec.config.NeoIdProperties;
import com.versatec.neoid.dto.NeoIdSignatureRequest;
import com.versatec.neoid.dto.NeoIdSignatureResponse;
import com.versatec.neoid.dto.NeoIdTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.UUID;

/**
 * Serviço responsável por toda a comunicação REST com a API NeoID (SerproID).
 * <p>
 * Encapsula os três passos do fluxo OAuth2 + assinatura remota:
 * <ol>
 *   <li>{@link #buildAuthorizationUrl(UUID)} — gera a URL OAuth2 para o titular abrir no celular.</li>
 *   <li>{@link #exchangeCodeForToken(String)} — troca o {@code authorization_code} por {@code access_token}.</li>
 *   <li>{@link #sendHashForSignature(String, byte[])} — envia o hash SHA-256 ao Serpro para assinatura remota.</li>
 * </ol>
 *
 * <p><b>Nota sobre credenciais</b>: {@code clientId} e {@code clientSecret} são fornecidos
 * pelo Serpro após credenciamento formal no Portal de Serviços. Configure via variáveis de
 * ambiente {@code NEOID_CLIENT_ID} e {@code NEOID_CLIENT_SECRET}.
 */
@Service
public class NeoIdOAuthService {

    private static final Logger log = LoggerFactory.getLogger(NeoIdOAuthService.class);

    private final NeoIdProperties properties;
    private final RestTemplate restTemplate;

    public NeoIdOAuthService(NeoIdProperties properties, RestTemplate restTemplate) {
        this.properties = properties;
        this.restTemplate = restTemplate;
    }

    // -------------------------------------------------------------------------
    // Passo 1 — Geração da URL de autorização OAuth2
    // -------------------------------------------------------------------------

    /**
     * Constrói a URL de autorização OAuth2 que o titular deve abrir no aplicativo NeoID.
     * <p>
     * O parâmetro {@code state} é preenchido com o {@code jobId} do
     * {@link com.versatec.domain.SignatureJob}, permitindo correlacionar o callback
     * com o job correto sem armazenar estado na sessão HTTP.
     *
     * @param jobId identificador do job de assinatura (usado como {@code state} OAuth2)
     * @return URL completa de autorização
     */
    public String buildAuthorizationUrl(UUID jobId) {
        String url = UriComponentsBuilder
                .fromHttpUrl(properties.getAuthorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.getClientId())
                .queryParam("redirect_uri", properties.getCallbackUrl())
                .queryParam("scope", "signature")
                .queryParam("state", jobId.toString())
                .toUriString();

        log.info("URL de autorização NeoID gerada para o job {}", jobId);
        return url;
    }

    // -------------------------------------------------------------------------
    // Passo 2 — Troca do authorization_code pelo access_token
    // -------------------------------------------------------------------------

    /**
     * Troca o {@code authorization_code} recebido no callback OAuth2 por um {@code access_token}.
     * <p>
     * Realiza um {@code POST /oauth/token} com {@code grant_type=authorization_code}
     * e {@code Content-Type: application/x-www-form-urlencoded}.
     *
     * @param code código de autorização recebido no callback do Serpro
     * @return {@link NeoIdTokenResponse} contendo o {@code access_token}
     * @throws NeoIdApiException se o Serpro retornar erro ou as credenciais forem inválidas
     */
    public NeoIdTokenResponse exchangeCodeForToken(String code) {
        log.info("Trocando authorization_code por access_token no NeoID");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", properties.getCallbackUrl());
        body.add("client_id", properties.getClientId());
        body.add("client_secret", properties.getClientSecret());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<NeoIdTokenResponse> response = restTemplate.postForEntity(
                    properties.getTokenEndpoint(),
                    request,
                    NeoIdTokenResponse.class
            );

            NeoIdTokenResponse tokenResponse = response.getBody();
            log.info("access_token obtido com sucesso. Expira em {} segundos",
                    tokenResponse != null ? tokenResponse.expiresIn() : "?");
            return tokenResponse;

        } catch (Exception e) {
            log.error("Falha ao trocar code por token no NeoID", e);
            throw new NeoIdApiException("Falha ao obter access_token do NeoID: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Passo 3 — Envio do hash para assinatura remota
    // -------------------------------------------------------------------------

    /**
     * Envia o hash SHA-256 do documento ao endpoint {@code /v1/signature} do NeoID
     * e retorna a assinatura CMS gerada pelo certificado A3 do titular.
     *
     * @param accessToken  token obtido no passo 2
     * @param documentHash hash SHA-256 do documento em bytes
     * @return {@link NeoIdSignatureResponse} com a assinatura CMS em Base64
     * @throws NeoIdApiException se o Serpro retornar erro na assinatura
     */
    public NeoIdSignatureResponse sendHashForSignature(String accessToken, byte[] documentHash) {
        log.info("Enviando hash do documento para assinatura remota no NeoID");

        String hashBase64 = Base64.getEncoder().encodeToString(documentHash);
        var requestBody = new NeoIdSignatureRequest(hashBase64);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);

        HttpEntity<NeoIdSignatureRequest> request = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<NeoIdSignatureResponse> response = restTemplate.postForEntity(
                    properties.getSignatureEndpoint(),
                    request,
                    NeoIdSignatureResponse.class
            );

            NeoIdSignatureResponse signatureResponse = response.getBody();
            log.info("Assinatura remota obtida com sucesso. Algoritmo: {}",
                    signatureResponse != null ? signatureResponse.signatureAlgorithm() : "?");
            return signatureResponse;

        } catch (Exception e) {
            log.error("Falha ao obter assinatura remota do NeoID", e);
            throw new NeoIdApiException("Falha ao obter assinatura do NeoID: " + e.getMessage(), e);
        }
    }
}
