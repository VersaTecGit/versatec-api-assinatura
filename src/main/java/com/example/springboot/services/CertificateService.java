package com.example.springboot.services;

import com.example.springboot.exceptions.WrongCertificatePasswordException;
import com.example.springboot.utils.FileUtils;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CertificateService {

    @Autowired
    FileUtils fileUtils;

    public KeyStore getKeyStore(Path certificatePath, String password)
            throws KeyStoreException,
            CertificateException,
            NoSuchAlgorithmException,
            WrongCertificatePasswordException
    {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (FileInputStream fileInputStream = new FileInputStream(certificatePath.toString())) {
            keyStore.load(fileInputStream, password.toCharArray());
            return keyStore;
        } catch (IOException e) {
            throw new WrongCertificatePasswordException("Wrong password");
        }
    }

    public void checkValidity(Path certificatePath, String password)
            throws WrongCertificatePasswordException,
            CertificateException,
            KeyStoreException,
            NoSuchAlgorithmException
    {
        var keyStore = getKeyStore(certificatePath, password);
        String alias = keyStore.aliases().nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        certificate.checkValidity(new Date());
    }

}
