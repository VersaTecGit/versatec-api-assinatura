package com.example.springboot.controllers;

import com.example.springboot.customs.FileLocationEnum;
import com.example.springboot.customs.WrongCertificatePasswordException;
import com.example.springboot.customs.CustomCertificate;
import com.example.springboot.customs.VisualSignatureConfig;
import com.example.springboot.services.SignatureService;
import com.example.springboot.utils.FileUtils;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Files;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

@RestController
@RequestMapping("/api/v1")
@Validated
public class SignerController {

    public final SignatureService signatureService;
    public final FileUtils fileUtils;

    public SignerController(SignatureService signatureService, FileUtils fileUtils) {
        this.signatureService = signatureService;
        this.fileUtils = fileUtils;
    }

    @PostMapping("/sign")
    public ResponseEntity<?> sign (
            @RequestParam(required = false) @NotNull MultipartFile file,
            @RequestParam(required = false) @NotNull MultipartFile certificate,
            @RequestParam(required = false) @NotNull @NotEmpty String password,
            @RequestParam(required = false) String url,
            @RequestParam(required = false) Integer pageIndex,
            @RequestParam(required = false) Integer x,
            @RequestParam(required = false) Integer y
    ) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);
        var certificatePath = this.fileUtils.uploadBytes(certificate, FileLocationEnum.UPLOAD);
        Path outputPath = null;

        try {
            VisualSignatureConfig visualSignatureConfig = null;
            if (pageIndex != null && x != null && y != null) {
                visualSignatureConfig = new VisualSignatureConfig(pageIndex, x, y);
            }

            var customCertificate = new CustomCertificate(certificatePath, password);
            byte[] signedDocument = this.signatureService.signDocument(filePath, customCertificate);

            outputPath = this.signatureService.createPDF(filePath, signedDocument, customCertificate, visualSignatureConfig, url);
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
            this.fileUtils.removeFile(outputPath);
        }
    }

    @PostMapping("/validate-signature")
    public ResponseEntity<String> validateSignature(
            @RequestParam(required = false) @NotNull MultipartFile file
    ) throws IOException {
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
    public ResponseEntity<String> validateCertificate(
            @RequestParam(value="certificate", required = false) @NotNull MultipartFile certificateFile,
            @RequestParam(required = false) @NotNull @NotEmpty String password
    ) throws IOException {
        var certificatePath = this.fileUtils.uploadBytes(certificateFile, FileLocationEnum.UPLOAD);

        try {
            var certificate = new CustomCertificate(certificatePath, password);
            certificate.checkValidity();
            return ResponseEntity.ok("Valid certificate");
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid certificate");
        } finally {
            this.fileUtils.removeFile(certificatePath);
        }
    }

    @GetMapping("/qr-code")
    public ResponseEntity<String> qrCode(
            @RequestParam(value = "_format", required = false) String format,
            @RequestParam(value = "_secretCode", required = false) String secretCode,
            @RequestParam(required = false) @NotNull @NotEmpty String url
    ) throws URISyntaxException {
        if (Objects.equals(format, "application/validador-iti json")) {
            return ResponseEntity.ok("{\"url\": \"" + url + "\"}");
        } else {
            var redirectUrl = new URI("https://validar.iti.gov.br/");
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setLocation(redirectUrl);
            return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
        }
    }
}
