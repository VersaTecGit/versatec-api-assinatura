package com.example.springboot.controllers;

import com.example.springboot.services.CheckSignerService;
import com.example.springboot.services.SignerService;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;
import java.security.KeyStore;
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
            @RequestParam("certificate") String certificate,
            @RequestParam("password") String password
    ) {
        try {
            this.signerService.uploadFile(file);

            Path certificatePath = this.signerService.getCertificatePath(certificate);

            KeyStore keyStore = this.signerService.getKeyStore(certificatePath, password);

            byte[] signedDocument = this.signerService.signDocument(file.getOriginalFilename(), keyStore, password);

            this.signerService.createPDF(file.getOriginalFilename(), signedDocument);

//            this.signerService.removeFile(file.getOriginalFilename());

            return ResponseEntity.ok("Signature completed");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/checkSigner")
    public ResponseEntity<String> checkSigner(@RequestParam("file") MultipartFile file) {
        try {
            this.signerService.uploadFile(file);
            String filePath = this.signerService.getFilePath(file.getOriginalFilename()).toString();

            List<SignatureInformations> results = this.checkSignerService.validateAllSignatures(filePath);

            if (!results.isEmpty()) {
                this.checkSignerService.printResult(results);

                return ResponseEntity.ok("Verification completed - Valid document");
            } else {
                return ResponseEntity.ok("Verification completed - Invalid document");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
