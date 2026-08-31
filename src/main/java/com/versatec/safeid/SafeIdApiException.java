package com.versatec.safeid;

/**
 * Exceção de runtime lançada quando ocorre uma falha na comunicação com a API SafeID (Safeweb PSC).
 * <p>
 * Segue o mesmo padrão de {@link com.versatec.neoid.NeoIdApiException}, permitindo
 * tratamento diferenciado por provedor no controller.
 */
public class SafeIdApiException extends RuntimeException {

    public SafeIdApiException(String message) {
        super(message);
    }

    public SafeIdApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
