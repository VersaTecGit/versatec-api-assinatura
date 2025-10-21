package com.versatec.services;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.WrongCertificatePasswordException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

@Service
public class SignatureService {

    private final TimeStampService timeStampService;

    @Autowired
    public SignatureService(TimeStampService timeStampService) {
        this.timeStampService = timeStampService;
    }

    /**
     * Assina um documento a partir de um arquivo e de um par de chaves.
     *
     * @param filePath          o nome do arquivo a ser assinado
     * @param customCertificate certificado contendo informações necessárias
     *
     * @return o documento assinado
     * @throws IOException                       se houver um erro ao ler o arquivo
     * @throws UnrecoverableKeyException         se a chave privada não puder ser
     *                                           recuperada
     * @throws KeyStoreException                 se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException          se o algoritmo de hash não é
     *                                           suportado
     * @throws WrongCertificatePasswordException se a senha do certificado estiver
     *                                           incorreta
     */
    public byte[] signDocument(Path filePath, CustomCertificate customCertificate)
            throws IOException,
            UnrecoverableKeyException,
            KeyStoreException,
            NoSuchAlgorithmException,
            WrongCertificatePasswordException {
        var signer = this.getPKCS7Signer(customCertificate);
        byte[] content = Files.readAllBytes(filePath);
        return signer.doAttachedSign(content);
    }

    /**
     * Retorna um objeto PKCS7Signer a partir de um certificado.
     *
     * @param customCertificate especialização do certificado, contendo informações
     *                          necessárias
     *
     * @return um objeto PKCS7Signer pronto para assinar um documento
     * @throws KeyStoreException         se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    PKCS7Signer getPKCS7Signer(CustomCertificate customCertificate)
            throws KeyStoreException,
            UnrecoverableKeyException,
            NoSuchAlgorithmException {
        var signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(customCertificate.certificateChain);
        signer.setPrivateKey((PrivateKey) customCertificate.keyStore.getKey(customCertificate.alias,
                customCertificate.password.toCharArray()));

        return signer;
    }

    /**
     * Assina um documento XML a partir de um arquivo e de um par de chaves.
     *
     * @param filePath          o nome do arquivo a ser assinado
     * @param customCertificate certificado contendo informações necessárias
     * @param timeStamp         Boleano que indica se a assinatura utilizará o
     *                          Carimbo do Tempo
     *
     * @return o documento assinado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws KeyStoreException         se houver um erro com o KeyStore
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    public byte[] signXmlDocument(Path filePath, CustomCertificate customCertificate, boolean timeStamp)
            throws Exception {

        var signer = this.getXmlSigner(customCertificate, timeStamp);
        Document signed = signer.signEnveloped(true, filePath.toString());

        byte[] bytes = this.documentToBytes(signed);

        return bytes;
    }

    /**
     * Retorna um objeto XMLSigner a partir de um certificado.
     *
     * @param customCertificate especialização do certificado, contendo informações
     *                          necessárias
     *
     * @return um objeto XMLSigner pronto para assinar um documento
     * @throws KeyStoreException         se o tipo de KeyStore não é suportado
     * @throws UnrecoverableKeyException se a chave privada não puder ser recuperada
     * @throws NoSuchAlgorithmException  se o algoritmo de hash não é suportado
     */
    XMLSigner getXmlSigner(CustomCertificate customCertificate, boolean timeStamp)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, Exception {
        var signer = new XMLSigner();
        signer.setPrivateKey((PrivateKey) customCertificate.keyStore.getKey(customCertificate.alias,
                customCertificate.password.toCharArray()));
        signer.setCertificateChain(customCertificate.certificateChain);

        if (timeStamp) {

            String accessToken = this.timeStampService.getAccessToken();

            TimeStampConfig.getInstance().setApiSERPRO(true);
            TimeStampConfig.getInstance().setClientCredentials(accessToken);
            signer.setPolicyId(XMLPoliciesOID.AD_RT_XADES_2_4.getOID());
        }

        return signer;
    }

    /**
     * Converte um objeto Document em um array de bytes.
     *
     * @param doc o objeto Document a ser convertido.
     *
     * @return um array de bytes.
     */
    private byte[] documentToBytes(Document doc) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(outputStream));
        return outputStream.toByteArray();
    }
}