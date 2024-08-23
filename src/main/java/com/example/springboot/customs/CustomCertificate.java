package com.example.springboot.customs;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CustomCertificate {

    public final String password;
    public final KeyStore keyStore;
    public final Certificate certificate;
    public final Certificate[] certificateChain;
    public final String alias;

    public CustomCertificate(Path path, String password)
            throws WrongCertificatePasswordException,
            CertificateException,
            KeyStoreException,
            NoSuchAlgorithmException
    {
        this.password = password;
        this.keyStore = getKeyStore(path, password);
        this.alias = this.keyStore.aliases().nextElement();
        this.certificate = this.keyStore.getCertificate(this.alias);
        this.certificateChain = this.keyStore.getCertificateChain(this.alias);
    }

    /**
     * Retorna um objeto KeyStore a partir de um arquivo de certificado e uma senha.
     *
     * @param certificatePath o caminho para o arquivo do certificado
     * @param password        a senha do arquivo de certificado
     *
     * @return um objeto KeyStore contendo o certificado
     * @throws KeyStoreException        se o tipo de KeyStore não é suportado
     * @throws CertificateException     se houver um erro ao carregar o certificado
     * @throws NoSuchAlgorithmException se o algoritmo de hash não é suportado
     * @throws WrongCertificatePasswordException  se houver um erro ao ler o arquivo de certificado
     */
    private static KeyStore getKeyStore(Path certificatePath, String password)
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

    /**
     * Verifica se o certificado é válido.
     *
     * @throws CertificateException se o certificado n o for válido
     */
    public void checkValidity() throws CertificateException
    {
        X509Certificate certificate = (X509Certificate) this.certificate;
        certificate.checkValidity(new Date());
    }


    /**
     * Retorna o identificador do certificado (CPF/CNPJ).
     *
     * @return identificador
     */
    public String getIdentifier()
    {
        var name = this.getX500Principal().getName();
        return name.split(":")[1].split(",")[0];
    }

    /**
     * Retorna o nome do certificado/nome do proprietário.
     *
     * @return nome
     */
    public String getCertificateName()
    {
        var name = this.getX500Principal().getName();
        return name.split(":")[0].replace("CN=", "");
    }

    /**
     * Converte o certificado em um objeto X500Principal.
     *
     * @return certificado X500Principal
     */
    private X500Principal getX500Principal()
    {
        return ((X509Certificate) (this.certificate)).getSubjectX500Principal();
    }
}
