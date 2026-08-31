package com.versatec.neoid;

/**
 * Exceção lançada quando a comunicação com a API NeoID (SerproID) falha.
 * <p>
 * Encapsula erros HTTP do Serpro (4xx, 5xx) e problemas de conectividade,
 * propagando uma mensagem clara para o {@link com.versatec.midlewares.GlobalExceptionHandler}.
 */
public class NeoIdApiException extends RuntimeException {

    public NeoIdApiException(String message) {
        super(message);
    }

    public NeoIdApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
