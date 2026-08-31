package com.versatec.safeid;

import com.versatec.config.SafeIdProperties;
import com.versatec.safeid.dto.SafeIdSignatureRequest;
import com.versatec.safeid.dto.SafeIdSignatureResponse;
import com.versatec.safeid.dto.SafeIdTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Serviço responsável por toda a comunicação REST com a API SafeID (Safeweb
 * PSC).
 * <p>
 * Encapsula os três passos do fluxo OAuth2 com PKCE + assinatura remota:
 * <ol>
 * <li>{@link #buildAuthorizationUrl(UUID, String)} — gera a URL OAuth2 com PKCE
 * para o titular.</li>
 * <li>{@link #exchangeCodeForToken(String, String)} — troca o {@code code} por
 * {@code access_token}.</li>
 * <li>{@link #sendHashForSignature(String, byte[], UUID)} — envia o hash ao
 * SafeID para assinatura.</li>
 * </ol>
 *
 * <p>
 * <b>Diferenças críticas em relação ao NeoID:</b>
 * <ul>
 * <li>A URL de autorização inclui os parâmetros PKCE {@code code_challenge} e
 * {@code code_challenge_method}.</li>
 * <li>A troca de código por token inclui o {@code code_verifier} (parâmetro
 * PKCE).</li>
 * <li>O hash do documento é enviado em <b>Base64</b> dentro de um array de
 * objetos estruturados.</li>
 * <li>O OID do SHA-256 é {@code 2.16.840.1.101.3.4.2.1}.</li>
 * </ul>
 */
@Service
public class SafeIdOAuthService {

    private static final Logger log = LoggerFactory.getLogger(SafeIdOAuthService.class);

    /** OID do algoritmo SHA-256 conforme RFC 5758. */
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";

    /** Formato de assinatura puro (RAW) necessário para injetar no XAdES. */
    private static final String SIGNATURE_FORMAT = "RAW";

    private final SafeIdProperties properties;
    private final RestTemplate restTemplate;

    public SafeIdOAuthService(SafeIdProperties properties, RestTemplate restTemplate) {
        this.properties = properties;
        this.restTemplate = restTemplate;
    }

    // -------------------------------------------------------------------------
    // Passo 1 — Geração da URL de autorização OAuth2 com PKCE
    // -------------------------------------------------------------------------

    /**
     * Constrói a URL de autorização OAuth2 do SafeID com os parâmetros PKCE.
     * <p>
     * O {@code state} é preenchido com o {@code jobId} para correlacionar o
     * callback
     * com o job correto sem manter estado na sessão HTTP.
     *
     * @param jobId         identificador do job de assinatura (usado como
     *                      {@code state} OAuth2)
     * @param codeChallenge desafio PKCE calculado pelo {@link SafeIdPkceUtils}
     * @return URL completa de autorização
     */
    public String buildAuthorizationUrl(UUID jobId, String codeChallenge) {
        String url = UriComponentsBuilder
                .fromHttpUrl(properties.getAuthorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.getClientId())
                .queryParam("redirect_uri", properties.getCallbackUrl())
                .queryParam("scope", "signature_session")
                .queryParam("state", jobId.toString())
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .toUriString();

        log.info("URL de autorização SafeID gerada para o job {}", jobId);
        return url;
    }

    // -------------------------------------------------------------------------
    // Passo 2 — Troca do authorization_code pelo access_token
    // -------------------------------------------------------------------------

    /**
     * Troca o {@code authorization_code} do callback por um {@code access_token}.
     * <p>
     * O {@code code_verifier} (parâmetro PKCE) é obrigatório e deve ser o mesmo
     * gerado no Passo 1 e armazenado no {@link com.versatec.domain.SignatureJob}.
     *
     * @param code         código de autorização recebido no callback do SafeID
     * @param codeVerifier verifier PKCE original recuperado do job
     * @return {@link SafeIdTokenResponse} contendo o {@code access_token}
     * @throws SafeIdApiException se o SafeID retornar erro ou credenciais inválidas
     */
    public SafeIdTokenResponse exchangeCodeForToken(String code, String codeVerifier) {
        log.info("Trocando authorization_code por access_token no SafeID");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", properties.getClientId());
        body.add("client_secret", properties.getClientSecret());
        body.add("code", code);
        body.add("redirect_uri", properties.getCallbackUrl());
        body.add("code_verifier", codeVerifier);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<SafeIdTokenResponse> response = restTemplate.postForEntity(
                    properties.getTokenEndpoint(),
                    request,
                    SafeIdTokenResponse.class);

            SafeIdTokenResponse tokenResponse = response.getBody();
            log.info("access_token SafeID obtido com sucesso. Expira em {} segundos. Titular: {} {}",
                    tokenResponse != null ? tokenResponse.expiresIn() : "?",
                    tokenResponse != null ? tokenResponse.authorizedIdentificationType() : "?",
                    tokenResponse != null ? tokenResponse.authorizedIdentification() : "?");
            return tokenResponse;

        } catch (HttpClientErrorException e) {
            log.error("Erro HTTP {} ao trocar code por token no SafeID: {}", e.getStatusCode(),
                    e.getResponseBodyAsString());
            throw new SafeIdApiException(
                    "Falha ao obter access_token do SafeID [" + e.getStatusCode() + "]: " + e.getResponseBodyAsString(),
                    e);
        } catch (Exception e) {
            log.error("Falha ao trocar code por token no SafeID", e);
            throw new SafeIdApiException("Falha ao obter access_token do SafeID: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Passo 3 — Envio do hash para assinatura remota
    // -------------------------------------------------------------------------

    /**
     * Envia o hash SHA-256 do documento ao endpoint {@code /oauth/signature} do
     * SafeID
     * e retorna as assinaturas produzidas pelo certificado A3 do titular.
     * <p>
     * O hash é enviado em <b>Base64</b> dentro de um objeto estruturado, junto com
     * o OID do algoritmo ({@code 2.16.840.1.101.3.4.2.1} para SHA-256) e o formato
     * de assinatura ({@code CMS}).
     *
     * @param accessToken  token obtido no Passo 2
     * @param documentHash hash SHA-256 do documento em bytes
     * @param jobId        identificador do job (usado como {@code id} do hash no
     *                     request)
     * @return {@link SafeIdSignatureResponse} com o array de assinaturas em Base64
     * @throws SafeIdApiException se o SafeID retornar erro na assinatura
     */
    public SafeIdSignatureResponse sendHashForSignature(String accessToken, byte[] documentHash, UUID jobId) {
        log.info("Enviando hash do documento para assinatura remota no SafeID (job {})", jobId);

        // Hash enviado em Base64 (não hexadecimal) conforme documentação SafeID
        String hashBase64 = Base64.getEncoder().encodeToString(documentHash);

        var hashItem = new SafeIdSignatureRequest.HashItem(
                jobId.toString(),
                "Documento " + jobId,
                hashBase64,
                SHA256_OID,
                SIGNATURE_FORMAT);

        var requestBody = new SafeIdSignatureRequest(null, List.of(hashItem));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);

        HttpEntity<SafeIdSignatureRequest> request = new HttpEntity<>(requestBody, headers);

        try {
            ResponseEntity<SafeIdSignatureResponse> response = restTemplate.postForEntity(
                    properties.getSignatureEndpoint(),
                    request,
                    SafeIdSignatureResponse.class);

            SafeIdSignatureResponse signatureResponse = response.getBody();
            int signaturesCount = signatureResponse != null && signatureResponse.signatures() != null
                    ? signatureResponse.signatures().size()
                    : 0;
            log.info("Assinatura remota SafeID obtida com sucesso. Total de assinaturas: {}", signaturesCount);
            return signatureResponse;

        } catch (HttpClientErrorException e) {
            log.error("Erro HTTP {} ao obter assinatura do SafeID: {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new SafeIdApiException(
                    "Falha ao obter assinatura do SafeID [" + e.getStatusCode() + "]: " + e.getResponseBodyAsString(),
                    e);
        } catch (Exception e) {
            log.error("Falha ao obter assinatura remota do SafeID", e);
            throw new SafeIdApiException("Falha ao obter assinatura do SafeID: " + e.getMessage(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Passo Intermediário — Obter Certificado Público do Titular
    // -------------------------------------------------------------------------

    /**
     * Obtém as informações e a cadeia do certificado público do titular.
     * Isso é essencial para que o Demoiselle possa montar a estrutura XAdES
     * envelopada (tag ds:X509Data) antes do cálculo do hash.
     *
     * @param accessToken token obtido no Passo 2
     * @return O certificado codificado em Base64
     */
    public String getCertificateInfo(String accessToken) {
        log.info("Obtendo certificado público do titular no SafeID");

        // Nota: A API SafeID possui o endpoint /oauth/certificate-discovery
        // De acordo com a SKILL, a URL base já contém "/oauth/" se configurado assim,
        // mas precisamos garantir que chamamos a rota correta baseada no tokenEndpoint.
        // Vamos extrair a base_url do tokenEndpoint.
        String baseUrl = properties.getTokenEndpoint().replace("/oauth/token", "");
        String url = baseUrl + "/oauth/certificate-discovery";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    request,
                    String.class);

            String jsonBody = response.getBody();
            log.info("Resposta do certificate-discovery: {}", jsonBody);

            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode root = mapper.readTree(jsonBody);

            if (root.has("certificates") && root.get("certificates").isArray() && root.get("certificates").size() > 0) {
                com.fasterxml.jackson.databind.JsonNode certNode = root.get("certificates").get(0);
                // Vamos tentar vários nomes comuns de atributos
                if (certNode.has("base64") && !certNode.get("base64").isNull())
                    return certNode.get("base64").asText();
                if (certNode.has("content") && !certNode.get("content").isNull())
                    return certNode.get("content").asText();
                if (certNode.has("certificate") && !certNode.get("certificate").isNull())
                    return certNode.get("certificate").asText();
                if (certNode.has("raw") && !certNode.get("raw").isNull())
                    return certNode.get("raw").asText();
            }
            // Se chegou aqui, não achou o certificado Base64. Vamos lançar o JSON bruto
            // para o usuário ver!
            throw new SafeIdApiException("Não encontrei o campo base64. JSON Retornado: " + jsonBody);

        } catch (HttpClientErrorException e) {
            log.error("Erro HTTP {} ao obter certificado do SafeID: {}", e.getStatusCode(),
                    e.getResponseBodyAsString());
            throw new SafeIdApiException(
                    "Falha ao obter certificado do SafeID [" + e.getStatusCode() + "]: " + e.getResponseBodyAsString(),
                    e);
        } catch (Exception e) {
            log.error("Falha ao obter certificado do SafeID", e);
            throw new SafeIdApiException("Falha ao obter certificado do SafeID: " + e.getMessage(), e);
        }
    }
}
