package com.versatec.signature.async;

import java.security.Provider;

public class VersatecProvider extends Provider {

    public VersatecProvider() {
        super("Versatec", 1.0, "Versatec Security Provider for Remote Signing");
        
        // Registra nossa implementação síncrona para interceptar assinaturas RSA
        put("Signature.SHA256withRSA", RemoteSignatureSpi.class.getName());
    }
}
