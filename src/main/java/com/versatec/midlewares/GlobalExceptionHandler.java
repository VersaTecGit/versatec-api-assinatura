package com.versatec.midlewares;

import com.versatec.neoid.NeoIdApiException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Intercepta exceções do tipo ConstraintViolationException. Para melhor retorno
     *
     * @param exception A exceção lançada
     *
     * @return Uma resposta HTTP com status 400 (Bad Request) e o corpo da resposta
     * contendo a mensagem de erro da exceção, dividida em uma lista de explicações.
     */
    @ExceptionHandler({ConstraintViolationException.class})
    public ResponseEntity<Object> handleConstraintViolationException(ConstraintViolationException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(exception.getMessage().split(", "));
    }

    /**
     * Intercepta falhas na comunicação com a API NeoID (Serpro).
     * Retorna 502 Bad Gateway indicando que o serviço externo não respondeu corretamente.
     *
     * @param exception exceção lançada pelo NeoIdOAuthService
     * @return 502 com mensagem descritiva
     */
    @ExceptionHandler(NeoIdApiException.class)
    public ResponseEntity<String> handleNeoIdApiException(NeoIdApiException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_GATEWAY)
                .body("Falha na comunicação com o NeoID (Serpro): " + exception.getMessage());
    }

    /**
     * Intercepta falhas na comunicação com a API SafeID.
     *
     * @param exception exceção lançada pelo SafeIdOAuthService ou Orchestrator
     * @return 502 com mensagem descritiva
     */
    @ExceptionHandler(com.versatec.safeid.SafeIdApiException.class)
    public ResponseEntity<String> handleSafeIdApiException(com.versatec.safeid.SafeIdApiException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_GATEWAY)
                .body("Falha no processamento do SafeID: " + exception.getMessage());
    }

    /**
     * Intercepta falhas de conversão de parâmetros de requisição (ex: enum inválido).
     * Ocorre quando, por exemplo, {@code signatureType=A!} é enviado em vez de {@code A1}.
     *
     * @param exception exceção lançada pelo Spring ao tentar converter um @RequestParam
     * @return 400 com mensagem indicando os valores aceitos
     */
    @ExceptionHandler(org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class)
    public ResponseEntity<String> handleMethodArgumentTypeMismatch(
            org.springframework.web.method.annotation.MethodArgumentTypeMismatchException exception) {

        String paramName = exception.getName();
        String invalidValue = String.valueOf(exception.getValue());
        Class<?> requiredType = exception.getRequiredType();

        String message;
        if (requiredType != null && requiredType.isEnum()) {
            Object[] constants = requiredType.getEnumConstants();
            String validValues = java.util.Arrays.stream(constants)
                    .map(Object::toString)
                    .collect(java.util.stream.Collectors.joining(", "));
            message = String.format(
                    "Valor inválido para o parâmetro '%s': '%s'. Valores aceitos: [%s].",
                    paramName, invalidValue, validValues);
        } else {
            message = String.format(
                    "Valor inválido para o parâmetro '%s': '%s'.",
                    paramName, invalidValue);
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception exception) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Erro interno do servidor durante o processamento: " + exception.getMessage());
    }
}