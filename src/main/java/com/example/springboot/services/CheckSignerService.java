package com.example.springboot.services;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class CheckSignerService {

    public List<SignatureInformations> validateAllSignatures(String filePath) throws IOException, ParseException, CMSException, CertificateException {
        List<SignatureInformations> results = new ArrayList<>();
        List<X509Certificate> chains = new ArrayList<X509Certificate>();
        PDDocument document;

        document = PDDocument.load(new File(filePath));
        List<SignatureInformations> result = null;

        int rangeMax = 0;
        int fileLen = 0;
        for (PDSignature sig : document.getSignatureDictionaries()) {
            COSDictionary sigDict = sig.getCOSObject();
            COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);

            Date signingTime = this.extractDateOfDictM(sigDict.getDictionaryObject(COSName.M));

            byte[] buf = null;

            try (FileInputStream fis = new FileInputStream(filePath)) {
                buf = sig.getSignedContent(fis);
            }

            ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
            configlcr.setOnline(false);

            PAdESChecker checker = new PAdESChecker();
            byte[] documentSignature = contents.getBytes();

//            File fileP7S = this.createFileP7S(filePath, documentSignature);

            try {
                result = checker.checkDetachedSignature(buf, documentSignature);
                checker.getSignaturesInfo().get(0).setSignDate(signingTime);
                int[] byteRange = sig.getByteRange();
                rangeMax = (byteRange[byteRange.length - 2] + byteRange[byteRange.length - 1]);
                fileLen = (int) new File(filePath).length();

                if (result == null || result.isEmpty()) {
                    System.err.println("Erro ao validar");
                }
                results.addAll(checker.getSignaturesInfo());
            } catch (SignerException e) {
                CMSSignedData signature = new CMSSignedData(documentSignature);

                SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
                Collection<X509CertificateHolder> certificateChain = signature.getCertificates()
                        .getMatches(signerInfo.getSID());

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                List<X509Certificate> certificates = new ArrayList<>();
                for (X509CertificateHolder certHolder : certificateChain) {
                    X509Certificate cert = (X509Certificate) certFactory
                            .generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
                    certificates.add(cert);
                }

                SignatureInformations resul = new SignatureInformations();
                BasicCertificate icpBrasilcertificate = new BasicCertificate(certificates.get(0));
                resul.setIcpBrasilcertificate(icpBrasilcertificate);
                String err = e.getMessage();
                LinkedList<String> erro = new LinkedList<String>();
                erro.add(err);
                resul.setValidatorErrors(erro);
                resul.setInvalidSignature(true);
                resul.setSignDate(signingTime);
                results.add(resul);
                chains.add(certificates.get(0));
            }
        }

        document.close();

        if (fileLen > rangeMax) {
            System.err.println("Erro! Foi identificado uma modificação incremental");
        }

        return results;
    }

    public void printResult(List<SignatureInformations> results) {
        for (SignatureInformations sis : results) {
            if (sis.isInvalidSignature()) {
                System.err.println("Assinatura inválida");
            } else {
                System.out.println("Assinatura válida");
            }

            if (sis.getSignDate() != null) {
                System.out.println("Data da assinatura: " + sis.getSignDate());
                System.out.println("Data da assinatura GMT: " + sis.getSignDateGMT());
            }

            for (String valErr : sis.getValidatorErrors()) {
                System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
                System.err.println(valErr);
            }

            for (String valWarn : sis.getValidatorWarnins()) {
                System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
                System.err.println(valWarn);
            }

            if (sis.getSignaturePolicy() != null) {
                System.out.println("------ Politica ----------------- ");
                System.out.println(sis.getSignaturePolicy().toString());

            }

            BasicCertificate bc = sis.getIcpBrasilcertificate();
            System.out.println(bc.toString());
            if (bc.hasCertificatePF()) {
                System.out.println(bc.getICPBRCertificatePF().getCPF());
            }
            if (bc.hasCertificatePJ()) {
                System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
                System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
            }

            if (sis.getTimeStampSigner() != null) {
                System.out.println(sis.getTimeStampSigner().toString());
            }

        }
    }

    private File createFileP7S(String filePath, byte[] documentSignature) throws IOException {
        File fileP7S = new File(filePath + "_.p7s");
        FileOutputStream os = new FileOutputStream(fileP7S);
        os.write(documentSignature);
        os.flush();
        os.close();

        return fileP7S;
    }

    private Date extractDateOfDictM(COSBase cosNameM) throws ParseException {
        String dateString = cosNameM.toString();
        dateString = dateString.replaceAll("^COSString\\{D:|\\}$", "");
        String gmt = "-" + dateString.split("-")[1].split("'")[0] + "00";
        dateString = dateString.replaceFirst("-\\d{2}'\\d{2}'", gmt);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssZ");
        Date date = formatter.parse(dateString);
        return date;
    }
}
