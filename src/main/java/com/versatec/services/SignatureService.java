package com.versatec.services;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.WrongCertificatePasswordException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

@Service
public class SignatureService {

    SignatureService() {
    }

    /**
     * Assina um documento a partir de um arquivo e de um par de chaves.
     *
     * @param filePath          o nome do arquivo a ser assinado
     * @param customCertificate certificado contendo informações necessárias
     *
     * @return o documento assinado
     * @throws IOException                          se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException            se a chave privada não puder ser recuperada
     * @throws KeyStoreException                    se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException             se o algoritmo de hash não é suportado
     * @throws WrongCertificatePasswordException    se a senha do certificado estiver incorreta
     */
    public byte[] signDocument(Path filePath, CustomCertificate customCertificate)
            throws IOException,
            UnrecoverableKeyException,
            KeyStoreException,
            NoSuchAlgorithmException,
            WrongCertificatePasswordException
    {
        var signer = this.getPKCS7Signer(customCertificate);
        byte[] content = Files.readAllBytes(filePath);
        return signer.doAttachedSign(content);
    }

    /**
     * Retorna um objeto PKCS7Signer a partir de um certificado.
     *
     * @param customCertificate especialização do certificado, contendo informações necessárias
     *
     * @return um objeto PKCS7Signer pronto para assinar um documento
     * @throws KeyStoreException         se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    PKCS7Signer getPKCS7Signer(CustomCertificate customCertificate)
            throws KeyStoreException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException
    {
        var signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(customCertificate.certificateChain);
        signer.setPrivateKey((PrivateKey) customCertificate.keyStore.getKey(customCertificate.alias, customCertificate.password.toCharArray()));

        return signer;
    }
}