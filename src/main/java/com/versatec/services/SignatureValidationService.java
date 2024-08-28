package com.versatec.services;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class SignatureValidationService {

    /**
     * Valida todas as assinaturas digitais em um documento PDF.
     *
     * @param filePath o caminho para o arquivo PDF a ser validado
     *
     * @return uma lista de informações sobre as assinaturas encontradas e o resultado da validação
     * @throws IOException          se ocorrer um erro de I/O
     * @throws ParseException       se ocorrer um erro ao analisar a data da assinatura
     * @throws CMSException         se ocorrer um erro relacionado ao CMS (Cryptographic Message Syntax)
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     */
    public List<SignatureInformations> validateAllSignatures(Path filePath)
            throws IOException,
            ParseException,
            CMSException,
            CertificateException
    {
        var results = new ArrayList<SignatureInformations>();
        var file = filePath.toFile();

        try (PDDocument document = PDDocument.load(file)) {
            for (var signature : document.getSignatureDictionaries()) {
                var cosDictionary = signature.getCOSObject();
                var documentSignature = this.getDocumentSignature(cosDictionary);

                var signingTime = this.extractDateOfDictM(cosDictionary.getDictionaryObject(COSName.M));
                var checker = new CAdESChecker();

                try {
                    this.processSignature(documentSignature, checker, signingTime, results);
                } catch (Exception e) {
                    this.processInvalidSignature(documentSignature, e, signingTime, results);
                }

                this.checkIncrementalModification(signature, filePath);
            }
        }

        return results;
    }

    /**
     * Extrai e analisa a data a partir do objeto COSBase que representa a data da assinatura.
     *
     * @param cosNameM o objeto COSBase que contém a data da assinatura no formato COSString
     *
     * @return a data extraída e analisada como um objeto {@link Date}
     * @throws ParseException se ocorrer um erro ao analisar a data do formato string para o formato {@link Date}
     */
    private Date extractDateOfDictM(COSBase cosNameM) throws ParseException {
        var dateString = cosNameM.toString();
        dateString = dateString.replaceAll("^COSString\\{D:|\\}$", "");
        var gmt = "-" + dateString.split("-")[1].split("'")[0] + "00";
        dateString = dateString.replaceFirst("-\\d{2}'\\d{2}'", gmt);
        var formatter = new SimpleDateFormat("yyyyMMddHHmmssZ");

        return formatter.parse(dateString);
    }

    /**
     * Obtém o conteúdo da assinatura a partir do dicionário de assinatura.
     *
     * @param cosDictionary o dicionário da assinatura
     *
     * @return o conteúdo da assinatura como um array de bytes
     */
    private byte[] getDocumentSignature(COSDictionary cosDictionary) {
        var contents = (COSString) cosDictionary.getDictionaryObject(COSName.CONTENTS);
        return contents.getBytes();
    }

    /**
     * Processa uma assinatura e adiciona suas informações à lista de resultados.
     *
     * @param documentSignature o conteúdo da assinatura
     * @param checker           o objeto para validação da assinatura
     * @param signingTime       a data da assinatura
     * @param results           a lista onde as informações da assinatura serão adicionadas
     */
    private void processSignature(
            byte[] documentSignature,
            CAdESChecker checker,
            Date signingTime,
            List<SignatureInformations> results
    ) {
        var result = checker.checkAttachedSignature(documentSignature);
        if (result != null && !result.isEmpty()) {
            checker.getSignaturesInfo().get(0).setSignDate(signingTime);
            results.addAll(checker.getSignaturesInfo());
        } else {
            System.err.println("Signature validation failed: no result.");
        }
    }

    /**
     * Processa uma assinatura inválida e registra as informações do erro.
     *
     * @param documentSignature o conteúdo da assinatura
     * @param e                 a exceção lançada durante a validação
     * @param signingTime       a data da assinatura
     * @param results           a lista onde as informações da assinatura inválida serão adicionadas
     *
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     * @throws IOException          se ocorrer um erro de I/O ao gerar certificados
     */
    private void processInvalidSignature(
            byte[] documentSignature,
            Exception e,
            Date signingTime,
            List<SignatureInformations> results
    )
            throws CertificateException,
            IOException,
            CMSException
    {
        var cmsSignedData = new CMSSignedData(documentSignature);
        var signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        Collection<X509CertificateHolder> certificateChain = cmsSignedData.getCertificates().getMatches(signerInfo.getSID());

        var certificates = extractCertificates(certificateChain);

        var result = new SignatureInformations();
        var basicCertificate = new BasicCertificate(certificates.get(0));
        result.setIcpBrasilcertificate(basicCertificate);
        result.setValidatorErrors(new LinkedList<>(List.of(e.getMessage())));
        result.setInvalidSignature(true);
        result.setSignDate(signingTime);
        results.add(result);
    }

    /**
     * Extrai certificados da cadeia de certificados obtida da assinatura.
     *
     * @param certificateChain a cadeia de certificados
     *
     * @return uma lista de certificados X509 extraídos
     * @throws CertificateException se ocorrer um erro ao processar os certificados
     * @throws IOException se ocorrer um erro de I/O ao gerar certificados
     */
    private List<X509Certificate> extractCertificates(Collection<X509CertificateHolder> certificateChain)
            throws CertificateException,
            IOException
    {
        var certFactory = CertificateFactory.getInstance("X.509");
        var certificates = new ArrayList<X509Certificate>();
        for (X509CertificateHolder certHolder : certificateChain) {
            var cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
            certificates.add(cert);
        }
        return certificates;
    }

    /**
     * Verifica se houve modificação incremental no arquivo PDF.
     *
     * @param signature a assinatura do documento
     * @param filePath o caminho para o arquivo PDF
     */
    private void checkIncrementalModification(PDSignature signature, Path filePath) {
        var byteRange = signature.getByteRange();
        var rangeMax = byteRange[byteRange.length - 2] + byteRange[byteRange.length - 1];
        var fileLen = (int) filePath.toFile().length();
        if (fileLen > rangeMax) {
            System.err.println("Error! Incremental modification detected.");
        }
    }
}