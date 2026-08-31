package com.versatec.safeid;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes unitários para {@link SafeIdPkceUtils}.
 * Verifica a geração e validação dos parâmetros PKCE (RFC 7636).
 */
class SafeIdPkceUtilsTest {

    private final SafeIdPkceUtils pkceUtils = new SafeIdPkceUtils();

    @Test
    void generateCodeVerifier_shouldHaveValidLength() {
        String verifier = pkceUtils.generateCodeVerifier();

        assertNotNull(verifier);
        // RFC 7636: code_verifier deve ter entre 43 e 128 caracteres
        assertTrue(verifier.length() >= 43 && verifier.length() <= 128,
                "code_verifier deve ter entre 43 e 128 caracteres, mas tem: " + verifier.length());
    }

    @Test
    void generateCodeVerifier_shouldUseOnlyAllowedCharacters() {
        String verifier = pkceUtils.generateCodeVerifier();

        // RFC 7636: apenas letras, dígitos e os caracteres - _ . ~
        assertTrue(verifier.matches("[A-Za-z0-9\\-._~]+"),
                "code_verifier contém caracteres inválidos: " + verifier);
    }

    @Test
    void generateCodeVerifier_shouldBeUnique() {
        String v1 = pkceUtils.generateCodeVerifier();
        String v2 = pkceUtils.generateCodeVerifier();

        assertNotEquals(v1, v2, "Cada chamada deve gerar um code_verifier diferente");
    }

    @Test
    void generateCodeChallenge_shouldBeDeterministic() throws Exception {
        String verifier = pkceUtils.generateCodeVerifier();

        String challenge1 = pkceUtils.generateCodeChallenge(verifier);
        String challenge2 = pkceUtils.generateCodeChallenge(verifier);

        assertEquals(challenge1, challenge2,
                "O mesmo code_verifier deve sempre gerar o mesmo code_challenge (SHA-256 é determinístico)");
    }

    @Test
    void generateCodeChallenge_shouldBeDifferentFromVerifier() throws Exception {
        String verifier = pkceUtils.generateCodeVerifier();
        String challenge = pkceUtils.generateCodeChallenge(verifier);

        assertNotEquals(verifier, challenge,
                "O code_challenge não deve ser igual ao code_verifier");
    }

    @Test
    void generateCodeChallenge_shouldBeBase64UrlEncoded() throws Exception {
        String verifier = pkceUtils.generateCodeVerifier();
        String challenge = pkceUtils.generateCodeChallenge(verifier);

        // Base64 URL-safe: não deve conter +, / ou = (padding)
        assertFalse(challenge.contains("+"), "code_challenge não deve conter '+'");
        assertFalse(challenge.contains("/"), "code_challenge não deve conter '/'");
        assertFalse(challenge.contains("="), "code_challenge não deve conter '=' (padding)");
    }

    @Test
    void pkceFlow_challengeShouldMatchVerifierViaS256() throws Exception {
        // Valida manualmente o fluxo S256:
        // challenge = BASE64URL(SHA256(ASCII(verifier)))
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String challenge = pkceUtils.generateCodeChallenge(verifier);

        // Valor esperado calculado independentemente para o verifier acima (RFC 7636 Appendix B)
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    }
}
