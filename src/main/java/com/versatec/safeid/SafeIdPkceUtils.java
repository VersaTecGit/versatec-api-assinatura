package com.versatec.safeid;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utilitário para geração dos parâmetros PKCE (Proof Key for Code Exchange) exigidos
 * pelo fluxo OAuth2 do SafeID, conforme especificado na RFC 7636.
 * <p>
 * O PKCE protege o fluxo de autorização contra ataques de interceptação de código:
 * <ol>
 *   <li>A aplicação gera um {@code code_verifier} aleatório e criptograficamente seguro.</li>
 *   <li>Calcula o {@code code_challenge} = BASE64URL(SHA-256({@code code_verifier})).</li>
 *   <li>Envia o {@code code_challenge} na requisição de autorização.</li>
 *   <li>No callback, envia o {@code code_verifier} original para validação pelo servidor.</li>
 * </ol>
 *
 * <p><b>Importante:</b> o {@code code_verifier} deve ser persistido no {@code SignatureJob}
 * (campo {@code codeVerifier}) pois é necessário no momento do callback.
 */
@Component
public class SafeIdPkceUtils {

    private static final int VERIFIER_BYTE_LENGTH = 64;

    /**
     * Gera um {@code code_verifier} criptograficamente seguro.
     * <p>
     * Produz 64 bytes aleatórios codificados em Base64URL sem padding,
     * resultando em uma string de 86 caracteres dentro do limite de 128 da RFC 7636.
     *
     * @return {@code code_verifier} Base64URL-encoded sem padding
     */
    public String generateCodeVerifier() {
        byte[] bytes = new byte[VERIFIER_BYTE_LENGTH];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Calcula o {@code code_challenge} a partir do {@code code_verifier}.
     * <p>
     * Algoritmo: {@code BASE64URL(SHA-256(ASCII(code_verifier)))} conforme RFC 7636.
     *
     * @param codeVerifier o verifier gerado em {@link #generateCodeVerifier()}
     * @return {@code code_challenge} Base64URL-encoded sem padding
     * @throws SafeIdApiException se o algoritmo SHA-256 não estiver disponível (improvável em JVM padrão)
     */
    public String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SafeIdApiException("Algoritmo SHA-256 não disponível para geração do PKCE", e);
        }
    }
}
