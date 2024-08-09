package com.example.springboot.controllers;

import com.example.springboot.records.VisualSignatureConfig;
import com.example.springboot.services.CheckSignerService;
import com.example.springboot.services.SignerService;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
public class SignerController {

    @Autowired
    SignerService signerService;

    @Autowired
    CheckSignerService checkSignerService;

    @PostMapping("/sign")
    public ResponseEntity<?> signer(
            @RequestParam("file") MultipartFile file,
//            @RequestParam("certificate") String certificate,
            @RequestParam("certificate") MultipartFile certificate,
            @RequestParam("password") String password,
            @RequestParam(value = "pageIndex", required = false) Integer pageIndex,
            @RequestParam(value = "x", required = false) Integer x,
            @RequestParam(value = "y", required = false) Integer y
    ) throws IOException {
        String fileHash = this.signerService.getRandomHash() + "_" + file.getOriginalFilename();
        String certificateHash = this.signerService.getRandomHash() + "_" + certificate.getOriginalFilename();

        try {
            this.signerService.uploadFile(file, fileHash, certificate, certificateHash);
            if( pageIndex != null && x != null  && y != null) {
                var vsc = new VisualSignatureConfig(pageIndex, x, y);
                this.signerService.setVisualSignatureConfig(vsc);
            }

//            Path certificatePath = this.signerService.getCertificatePath(certificate);

            KeyStore keyStore = this.signerService.getKeyStore(certificateHash, password);

            byte[] signedDocument = this.signerService.signDocument(fileHash, keyStore, password);

            byte[] signedPdfData = this.signerService.createPDF(fileHash, signedDocument, keyStore);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_" + file.getOriginalFilename());

            this.signerService.removeAllFiles(fileHash, certificateHash);

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(signedPdfData.length)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(signedPdfData);
        } catch (Exception e) {
            this.signerService.removeAllFiles(fileHash, certificateHash);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/validate-signature")
    public ResponseEntity<String> checkSigner(@RequestParam("file") MultipartFile file) throws IOException {
        String fileHash = this.signerService.getRandomHash() + "_" + file.getOriginalFilename();

        try {
            this.signerService.uploadFile(file, fileHash, null, null);
            String filePath = this.signerService.getFilePath(fileHash).toString();
//
            List<SignatureInformations> results = this.checkSignerService.validateAllSignatures(filePath);

            this.signerService.removeAllFiles(fileHash, null);

            if (!results.isEmpty()) {
                this.checkSignerService.printResult(results);

                return ResponseEntity.ok("Valid document");
            } else {
                return ResponseEntity.ok("Invalid document");
            }
        } catch (Exception e) {
            this.signerService.removeAllFiles(fileHash, null);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/validate-certificate")
    public ResponseEntity<String> checkCertificate(
            @RequestParam("certificate") MultipartFile certificate,
            @RequestParam("password") String password
    ) throws IOException {
        String certificateHash = this.signerService.getRandomHash() + "_" + certificate.getOriginalFilename();

        try {
            this.signerService.uploadFile(null, null, certificate, certificateHash);

            KeyStore keyStore = this.signerService.getKeyStore(certificateHash, password);

            String alias = keyStore.aliases().nextElement();
            X509Certificate certificateResult = (X509Certificate) keyStore.getCertificate(alias);

            certificateResult.checkValidity(new Date());

            //// Caso precise buscar os dados do certificado
            // BasicCertificate bc = new BasicCertificate(certificate);

            this.signerService.removeAllFiles(null, certificateHash);

            return ResponseEntity.ok("Valid certificate");
        } catch (Exception e) {
            this.signerService.removeAllFiles(null, certificateHash);
            return ResponseEntity.ok("Invalid certificate");
        }
    }
}
