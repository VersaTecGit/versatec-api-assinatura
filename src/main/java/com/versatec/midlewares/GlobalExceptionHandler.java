package com.versatec.midlewares;

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
}