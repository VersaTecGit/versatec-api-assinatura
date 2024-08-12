package com.example.springboot.exceptions;

public class WrongCertificatePasswordException extends Exception {

    public WrongCertificatePasswordException(String message) {
        super(message);
    }
}
