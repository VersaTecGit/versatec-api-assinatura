package com.versatec.signature.async;

import com.versatec.safeid.dto.SafeIdSignatureResponse;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Base64;
import java.util.UUID;

public class RemoteSignatureSpi extends SignatureSpi {

    private MessageDigest digest;
    private RemotePrivateKey currentKey;

    public RemoteSignatureSpi() {
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 indisponível", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("RemoteSignatureSpi serve apenas para assinar.");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof RemotePrivateKey)) {
            throw new InvalidKeyException("RemoteSignatureSpi requer um RemotePrivateKey");
        }
        this.currentKey = (RemotePrivateKey) privateKey;
        this.digest.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        this.digest.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.digest.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (currentKey == null) {
            throw new SignatureException("Não inicializado para assinatura");
        }

        UUID jobId = currentKey.getJobId();
        byte[] hash = digest.digest();

        try {
            // Faz a requisição síncrona para o SafeID!
            // Estamos rodando dentro da thread de callback, o que não tem problema,
            // pois o callback só retorna para o navegador quando o processo estiver concluído.
            SafeIdSignatureResponse response = currentKey.getOAuthService()
                    .sendHashForSignature(currentKey.getAccessToken(), hash, jobId);

            if (response == null || response.signatures() == null || response.signatures().isEmpty()) {
                throw new SignatureException("SafeID não retornou a assinatura");
            }

            // O formato RAW retorna base64 puro (ou base64url dependendo do provedor)
            String rawBase64 = response.signatures().get(0).rawSignature();
            // Normalizar caso venha em Base64URL
            String normalizedBase64 = rawBase64.replace('-', '+').replace('_', '/');
            return Base64.getDecoder().decode(normalizedBase64);

        } catch (Exception e) {
            throw new SignatureException("Erro ao solicitar assinatura remota: " + e.getMessage(), e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new UnsupportedOperationException("RemoteSignatureSpi serve apenas para assinar.");
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
