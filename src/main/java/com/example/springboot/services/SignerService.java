package com.example.springboot.services;

import com.example.springboot.FileStorageProperties;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Objects;
import java.util.TimeZone;

@Service
public class SignerService {

    private final Path fileUploadLocation;
    private final Path fileDownloadLocation;

    public SignerService(FileStorageProperties fileStorageLocation) {
        this.fileUploadLocation = Paths.get(fileStorageLocation.getUploadDir()).toAbsolutePath().normalize();
        this.fileDownloadLocation = Paths.get(fileStorageLocation.getDownloadDir()).toAbsolutePath().normalize();
    }

    public void uploadFile(MultipartFile file) throws IOException {
        //TODO Add hash in name
        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
        Path targetFileLocation = this.fileUploadLocation.resolve(fileName);
        file.transferTo(targetFileLocation);
    }

    public void removeFile(String fileName) throws IOException {
        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        Files.deleteIfExists(filePath);
    }

    public Path getCertificatePath(String certificate) {
        //TODO Change default location
        String location = "C:\\Projetos\\springboot\\" + certificate;

        return Paths.get(location);
    }

    public KeyStore getKeyStore(Path certificatePath, String password) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        FileInputStream fileInputStream = new FileInputStream(certificatePath.toString());
        keyStore.load(fileInputStream, password.toCharArray());

        return keyStore;
    }

    public byte[] signDocument(String fileName, KeyStore ks, String password) throws IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        PKCS7Signer signer = getPKCS7Signer(ks, password);

        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        byte[] content = Files.readAllBytes(filePath);

        return signer.doAttachedSign(content);
    }

    public void createPDF(String fileName, byte[] signedDocument) throws IOException {
        Path filePath = this.fileUploadLocation.resolve(fileName).normalize();
        File fileIn = new File(filePath.toString());
        PDDocument originalDocument = PDDocument.load(fileIn);

        Path downloadPath = this.fileDownloadLocation.resolve(this.addSignatureName(fileName)).normalize();
        OutputStream output = new FileOutputStream(downloadPath.toString());

        PDSignature signature = this.getPDSignature();

        originalDocument.addSignature(signature, this.getSignatureOptions());

        ExternalSigningSupport externalSigning = originalDocument.saveIncrementalForExternalSigning(output);
        externalSigning.setSignature(signedDocument);

        originalDocument.saveIncremental(output);
    }

    public Path getFilePath(String fileName) {
        return this.fileUploadLocation.resolve(fileName).normalize();
    }

    private PKCS7Signer getPKCS7Signer(KeyStore ks, String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        String alias = ks.aliases().nextElement();

        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(ks.getCertificateChain(alias));
        signer.setPrivateKey((PrivateKey) ks.getKey(alias, password.toCharArray()));
//        signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_3);
//        signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);

        return signer;
    }

    private PDSignature getPDSignature() {
        PDSignature signature = new PDSignature();
        signature.setSignDate(Calendar.getInstance(TimeZone.getTimeZone("America/Sao_Paulo")));
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
//        signature.setName(alias);
//        signature.setLocation("Caratinga, MG");
//        signature.setReason("Assinatura");

        return signature;
    }

    private SignatureOptions getSignatureOptions() {
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setPreferredSignatureSize(200000);

        return signatureOptions;
    }

    private String addSignatureName(String fileName) {
        int indicePonto = fileName.lastIndexOf('.');
        if (indicePonto != -1) {
            String name = fileName.substring(0, indicePonto);
            String extension = fileName.substring(indicePonto);

            return name + "_assinado" + extension;
        }
        return fileName;
    }
}
