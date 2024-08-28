package com.versatec.controllers;

import com.versatec.customs.FileLocationEnum;
import com.versatec.customs.WrongCertificatePasswordException;
import com.versatec.customs.CustomCertificate;
import com.versatec.customs.VisualSignatureConfig;
import com.versatec.services.SignatureFileService;
import com.versatec.services.SignatureService;
import com.versatec.services.SignatureValidationService;
import com.versatec.utils.FileUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.media.Content;
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
import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.responses.*;
import io.swagger.v3.oas.annotations.media.*;

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
    public final SignatureFileService signatureFileService;
    public final SignatureValidationService signatureValidationService;
    public final FileUtils fileUtils;
    public final ObjectMapper objectMapper;

    public SignerController(
            SignatureService signatureService,
            SignatureFileService signatureFileService,
            SignatureValidationService signatureValidationService,
            FileUtils fileUtils,
            ObjectMapper objectMapper
    ) {
        this.signatureService = signatureService;
        this.signatureFileService = signatureFileService;
        this.signatureValidationService = signatureValidationService;
        this.fileUtils = fileUtils;
        this.objectMapper = objectMapper;
    }

    @PostMapping(path = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Assinar Documento",
            description = "Assina um documento com assinador CADES, e certificado A1. <br/>" +
                    "Caso seja enviada a URL onde o documento irá ser hospedado, inclui o QR CODE. <br/>" +
                    "PageIndex, X, e Y, são parâmetros para customização da posição da assinatura visual",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Documento assinado com sucesso",
                            content = @Content(
                                    mediaType = "application/pdf"
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String[].class)
                            )
                    ),
                    @ApiResponse(responseCode = "401", description = "Senha do certificado é inválida",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String.class)
                            )
                    ),
                    @ApiResponse(responseCode = "403", description = "Certificado inválido",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String.class)
                            )
                    ),
            })
    public ResponseEntity<?> sign(
            @RequestParam(required = false) @NotNull MultipartFile file,
            @RequestParam(required = false) @NotNull MultipartFile certificate,
            @RequestParam(required = false) @NotNull @NotEmpty String password,
            @RequestParam(required = false) String url,
            @RequestParam(required = false) Integer pageIndex,
            @RequestParam(required = false) Integer x,
            @RequestParam(required = false) Integer y
    ) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);
        var certificatePath = this.fileUtils.uploadFile(certificate, FileLocationEnum.UPLOAD);
        Path outputPath = null;

        try {
            var visualSignatureConfig = new VisualSignatureConfig(pageIndex, x, y);
            var customCertificate = new CustomCertificate(certificatePath, password);

            byte[] signedDocument = this.signatureService.signDocument(filePath, customCertificate);
            outputPath = this.signatureFileService.createPDF(filePath, signedDocument, customCertificate, visualSignatureConfig, url);

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

    @PostMapping(path = "/validate-signature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Validar assinatura",
            description = "Valida se todas as assinaturas de um documento são válidas",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Documento assinado com sucesso",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String.class)
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String[].class)
                            )
                    )
            })
    public ResponseEntity<String> validateSignature(
            @RequestParam(required = false) @NotNull MultipartFile file
    ) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);

        try {
            List<SignatureInformations> results = this.signatureValidationService.validateAllSignatures(filePath);

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

    @PostMapping(path = "/validate-certificate", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Validar certificado",
            description = "Valida se um certificado é valido",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Documento assinado com sucesso",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String.class)
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String[].class)
                            )
                    ),
                    @ApiResponse(responseCode = "401", description = "Senha do certificado é inválida",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String.class)
                            )
                    )
            })
    public ResponseEntity<String> validateCertificate(
            @RequestParam(required = false) @NotNull MultipartFile certificate,
            @RequestParam(required = false) @NotNull @NotEmpty String password
    ) throws IOException {
        var certificatePath = this.fileUtils.uploadFile(certificate, FileLocationEnum.UPLOAD);

        try {
            var customCertificate = new CustomCertificate(certificatePath, password);
            customCertificate.checkValidity();
            return ResponseEntity.ok("Valid certificate");
        } catch (WrongCertificatePasswordException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.ok("Invalid certificate");
        } finally {
            this.fileUtils.removeFile(certificatePath);
        }
    }

    @GetMapping("/qr-code")
    @Operation(
            summary = "Url na qual os Qr Codes apontam",
            description = "Caso lido pela câmera do celular, redireciona o usuário para o site validar.iti.gov.br. <br/>" +
                    "Caso lido pelo validador do site, retorna um json com a URL do pdf, para o site realizar o download do arquivo",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Json com url do documento",
                            content = @Content(
                                    mediaType = "application/json"
                            )
                    ),
                    @ApiResponse(responseCode = "303", description = "Redirecionamento para validar.iti.gov.br",
                            content = @Content(
                                    mediaType = ""
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = String[].class)
                            )
                    ),
            })
    public ResponseEntity<String> qrCode(
            @RequestParam(value = "_format", required = false) String format,
            @RequestParam(value = "_secretCode", required = false) String secretCode,
            @RequestParam(value = "url", required = false) @NotNull @NotEmpty String returnUrl
    ) throws URISyntaxException, JsonProcessingException {
        if (Objects.equals(format, "application/validador-iti json")) {
            var result = new Object(){
                final String url = returnUrl;
            };
            String json = this.objectMapper.writeValueAsString(result);
            return ResponseEntity.ok(json);
        } else {
            var redirectUrl = new URI("https://validar.iti.gov.br/");
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setLocation(redirectUrl);
            return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
        }
    }
}
