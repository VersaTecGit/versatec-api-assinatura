package com.versatec.services;

import com.versatec.customs.CustomCertificate;
import com.versatec.customs.WrongCertificatePasswordException;
import com.versatec.customs.XmlNodeNotFoundException;
import com.versatec.utils.XmlNodeLocator;
import com.versatec.utils.XmlNodeSigner;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
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
    private final XmlNodeLocator xmlNodeLocator;
    private final XmlNodeSigner xmlNodeSigner;

    @Autowired
    public SignatureService(
            TimeStampService timeStampService,
            XmlNodeLocator xmlNodeLocator,
            XmlNodeSigner xmlNodeSigner) {
        this.timeStampService = timeStampService;
        this.xmlNodeLocator = xmlNodeLocator;
        this.xmlNodeSigner = xmlNodeSigner;
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

            String accessToken = this.timeStampService.getEncodedCredentials();

            TimeStampConfig.getInstance().setApiSERPRO(true);
            TimeStampConfig.getInstance().setClientCredentials(accessToken);
            signer.setPolicyId(XMLPoliciesOID.AD_RT_XADES_2_4.getOID());
        }

        return signer;
    }

    /**
     * Signs a specific node inside an XML document identified by an XPath expression.
     *
     * <p>This method keeps the rest of the document — including any signatures already
     * present — completely intact. It is designed for scenarios that require multiple
     * independent signatures on different nodes of the same XML (e.g. Digital Diplomas
     * with separate IES Emissora and IES Registradora signatures).</p>
     *
     * @param filePath          path to the XML file to be signed
     * @param customCertificate certificate and private key used for signing
     * @param targetXPath       XPath expression pointing to the element that will
     *                          receive the enveloped {@code <ds:Signature>} as a child
     * @return the serialised XML document with the new signature appended to the target node
     * @throws XmlNodeNotFoundException if {@code targetXPath} does not match any element
     * @throws Exception                on any cryptographic or XML processing error
     */
    public byte[] signXmlDocumentAtNode(
            Path filePath,
            CustomCertificate customCertificate,
            String targetXPath) throws Exception {

        Document document = parseXmlToDocument(filePath);
        Element targetElement = xmlNodeLocator.locate(document, targetXPath);
        xmlNodeSigner.signElement(document, targetElement, customCertificate);
        return documentToBytes(document);
    }

    /**
     * Parses the XML file at the given path into a DOM {@link Document}.
     *
     * @param filePath path to the XML file
     * @return the parsed DOM document
     * @throws Exception if the file cannot be read or parsed
     */
    private Document parseXmlToDocument(Path filePath) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(filePath.toFile());
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