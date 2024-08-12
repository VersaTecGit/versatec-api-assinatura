package com.example.springboot.controllers;

import com.example.springboot.enums.FileLocationEnum;
import com.example.springboot.exceptions.WrongCertificatePasswordException;
import com.example.springboot.services.CertificateService;
import com.example.springboot.services.SignatureService;
import com.example.springboot.utils.FileUtils;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
public class SignerController {

    @Autowired
    SignatureService signatureService;

    @Autowired
    CertificateService certificateService;

    @Autowired
    FileUtils fileUtils;

    @PostMapping("/sign")
    public ResponseEntity<?> signer(
            @RequestParam("file") MultipartFile file,
            @RequestParam("certificate") MultipartFile certificate,
            @RequestParam("password") String password,
            @RequestParam(value = "pageIndex", required = false) Integer pageIndex,
            @RequestParam(value = "x", required = false) Integer x,
            @RequestParam(value = "y", required = false) Integer y
    ) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);
        var certificatePath = this.fileUtils.uploadBytes(certificate, FileLocationEnum.UPLOAD);
        Path outputPath = null;

        try {
            var keyStore = this.certificateService.getKeyStore(certificatePath, password);

            byte[] signedDocument = this.signatureService.signDocument(filePath, keyStore, password);

            outputPath = this.signatureService.createPDF(filePath, signedDocument, keyStore);
            var signedPdfData = Files.readAllBytes(outputPath);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=signed_" + file.getOriginalFilename());

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentLength(signedPdfData.length)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(signedPdfData);
        } catch (WrongCertificatePasswordException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (CertificateValidatorException e) {
            return ResponseEntity.status(403).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } finally {
            this.fileUtils.removeFile(filePath);
            this.fileUtils.removeFile(certificatePath);
            if(outputPath != null) {
                this.fileUtils.removeFile(outputPath);
            }
        }
    }

    @PostMapping("/validate-signature")
    public ResponseEntity<String> checkSigner(@RequestParam("file") MultipartFile file) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);

        try {
            List<SignatureInformations> results = this.signatureService.validateAllSignatures(filePath);

            if (!results.isEmpty()) {
                return ResponseEntity.ok("Valid document");
            } else {
                return ResponseEntity.ok("Invalid document");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } finally {
            this.fileUtils.removeFile(filePath);
        }
    }

    @PostMapping("/validate-certificate")
    public ResponseEntity<String> checkCertificate(
            @RequestParam("certificate") MultipartFile certificate,
            @RequestParam("password") String password
    ) throws IOException {
        var certificatePath = this.fileUtils.uploadBytes(certificate, FileLocationEnum.UPLOAD);

        try {
            this.certificateService.checkValidity(certificatePath, password);
            return ResponseEntity.ok("Valid certificate");
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid certificate");
        } finally {
            this.fileUtils.removeFile(certificatePath);
        }
    }
}
