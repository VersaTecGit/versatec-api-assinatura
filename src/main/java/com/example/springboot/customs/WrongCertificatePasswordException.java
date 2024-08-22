package com.example.springboot.customs;

public class WrongCertificatePasswordException extends Exception {

    public WrongCertificatePasswordException(String message) {
        super(message);
    }
}
