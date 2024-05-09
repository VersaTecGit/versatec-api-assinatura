package com.example.springboot.controllers;

import com.example.springboot.services.CheckSignerService;
import com.example.springboot.services.SignerService;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

@RestController
public class SignerController {

    @Autowired
    SignerService signerService;

    @Autowired
    CheckSignerService checkSignerService;

    @PostMapping("/signer")
    public ResponseEntity<String> signer(
            @RequestParam("file") MultipartFile file,
//            @RequestParam("certificate") String certificate,
            @RequestParam("certificateFile") MultipartFile certificateFile,
            @RequestParam("password") String password
    ) {
        try {
            this.signerService.uploadFile(file, certificateFile);

//            Path certificatePath = this.signerService.getCertificatePath(certificate);

            KeyStore keyStore = this.signerService.getKeyStore(certificateFile.getOriginalFilename(), password);

            byte[] signedDocument = this.signerService.signDocument(file.getOriginalFilename(), keyStore, password);

            this.signerService.createPDF(file.getOriginalFilename(), signedDocument, keyStore);

//            this.signerService.removeFile(file.getOriginalFilename());

            return ResponseEntity.ok("Signature completed");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/checkSigner")
    public ResponseEntity<String> checkSigner(@RequestParam("file") MultipartFile file) {
        try {
            this.signerService.uploadFile(file, null);
            String filePath = this.signerService.getFilePath(file.getOriginalFilename()).toString();

            List<SignatureInformations> results = this.checkSignerService.validateAllSignatures(filePath);

            if (!results.isEmpty()) {
                this.checkSignerService.printResult(results);

                return ResponseEntity.ok("Valid document");
            } else {
                return ResponseEntity.ok("Invalid document");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/checkCertificate")
    public ResponseEntity<String> checkCertificate(
            @RequestParam("certificateFile") MultipartFile certificateFile,
            @RequestParam("password") String password
    ) {
        try {
            this.signerService.uploadFile(null, certificateFile);

            KeyStore keyStore = this.signerService.getKeyStore(certificateFile.getOriginalFilename(), password);

            String alias = keyStore.aliases().nextElement();
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

            Date dataAtual = new Date();

            //// Incrementar 10 anos na data atual para testar a validação!
//            Calendar calendar = Calendar.getInstance();
//            calendar.setTime(dataAtual);
//            calendar.add(Calendar.YEAR, 10);
//            Date dataFutura = calendar.getTime();

            certificate.checkValidity(dataAtual);

            //// Caso precise buscar os dados do certificado
//            BasicCertificate bc = new BasicCertificate(certificate);

            return ResponseEntity.ok("Valid certificate");
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid certificate");
        }
    }
}
