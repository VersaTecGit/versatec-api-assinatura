package com.versatec.signature.async;

import com.versatec.safeid.SafeIdOAuthService;

import java.security.PrivateKey;
import java.util.UUID;

public class RemotePrivateKey implements PrivateKey {

    private final String accessToken;
    private final SafeIdOAuthService oAuthService;
    private final UUID jobId;

    public RemotePrivateKey(String accessToken, SafeIdOAuthService oAuthService, UUID jobId) {
        this.accessToken = accessToken;
        this.oAuthService = oAuthService;
        this.jobId = jobId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public SafeIdOAuthService getOAuthService() {
        return oAuthService;
    }

    public UUID getJobId() {
        return jobId;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
