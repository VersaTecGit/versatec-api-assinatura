package com.versatec.domain;

/**
 * Define o tipo de provedor de assinatura digital a ser utilizado.
 * <p>
 * - {@link #A1}: Assinatura via certificado A1 residente no servidor (.pfx/.p12).
 *   Fluxo síncrono — a resposta retorna o documento assinado imediatamente.
 * <p>
 * - {@link #NEOID}: Assinatura via Certificado A3 em Nuvem (SerproID/NeoID).
 *   Fluxo assíncrono OAuth2 — o titular aprova a assinatura no aplicativo móvel.
 *   A resposta retorna um {@code jobId} e uma {@code authorizationUrl}.
 * <p>
 * - {@link #SAFEID}: Assinatura via Certificado A3 em Nuvem (Safeweb PSC).
 *   Fluxo assíncrono OAuth2 com PKCE — o titular aprova a assinatura no aplicativo SafeID.
 *   A resposta retorna um {@code jobId} e uma {@code authorizationUrl}.
 */
public enum SignatureType {
    A1,
    NEOID,
    SAFEID
}
