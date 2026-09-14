package com.versatec.controllers;

import com.versatec.customs.FileLocationEnum;
import com.versatec.customs.WrongCertificatePasswordException;
import com.versatec.customs.CustomCertificate;
import com.versatec.customs.VisualSignatureConfig;
import com.versatec.customs.XmlNodeNotFoundException;
import com.versatec.domain.JobStatus;
import com.versatec.domain.SignatureType;
import com.versatec.repository.SignatureJobRepository;
import com.versatec.services.SignatureFileService;
import com.versatec.services.SignatureValidationService;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import com.versatec.signature.orchestrator.NeoIdCallbackOrchestrator;
import com.versatec.signature.orchestrator.SafeIdCallbackOrchestrator;
import com.versatec.signature.resolver.SignatureStrategyResolver;
import com.versatec.services.SignatureService;
import com.versatec.utils.FileUtils;
import com.versatec.utils.XmlNodeLocator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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
import org.springframework.web.server.ResponseStatusException;

import io.swagger.v3.oas.annotations.*;
import io.swagger.v3.oas.annotations.responses.*;
import io.swagger.v3.oas.annotations.media.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
    public final SignatureStrategyResolver signatureStrategyResolver;
    public final NeoIdCallbackOrchestrator neoIdCallbackOrchestrator;
    public final SafeIdCallbackOrchestrator safeIdCallbackOrchestrator;
    public final SignatureJobRepository signatureJobRepository;
    public final XmlNodeLocator xmlNodeLocator;

    public SignerController(
            SignatureService signatureService,
            SignatureFileService signatureFileService,
            SignatureValidationService signatureValidationService,
            FileUtils fileUtils,
            ObjectMapper objectMapper,
            SignatureStrategyResolver signatureStrategyResolver,
            NeoIdCallbackOrchestrator neoIdCallbackOrchestrator,
            SafeIdCallbackOrchestrator safeIdCallbackOrchestrator,
            SignatureJobRepository signatureJobRepository,
            XmlNodeLocator xmlNodeLocator) {
        this.signatureService = signatureService;
        this.signatureFileService = signatureFileService;
        this.signatureValidationService = signatureValidationService;
        this.fileUtils = fileUtils;
        this.objectMapper = objectMapper;
        this.signatureStrategyResolver = signatureStrategyResolver;
        this.neoIdCallbackOrchestrator = neoIdCallbackOrchestrator;
        this.safeIdCallbackOrchestrator = safeIdCallbackOrchestrator;
        this.signatureJobRepository = signatureJobRepository;
        this.xmlNodeLocator = xmlNodeLocator;
    }

    @PostMapping(path = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Assinar Documento", description = "Assina um documento com assinador <b>CADES</b>, e certificado <b>A1</b>. <br/>"
            +
            "Caso seja enviada a <b>URL</b> onde o documento irá ser hospedado, inclui o <b>QR CODE</b>. <br/>"
            +
            "<b>PageIndex</b>, <b>X</b>, e <b>Y</b>, são parâmetros opcionais para customização da posição da assinatura visual. <br/><br/>"
            +
            "<b>PageIndex</b>: Começa de 0 e vai até o numero de páginas do documento -1. Para escolher automaticamente a "
            +
            "última página pode se enviar -1.<br/>" +
            "<b>X</b>: Margem a saltar do lado esquerdo da página. Valor padrão de assinatura sem QR: (Paisagem)356. (Retrato)233. <br/>"
            +
            "<b>Y</b>: Margem a saltar do lado inferior da página. Valor padrão de assinatura sem QR: 45. <br/>"
            +
            "<b>AllPages</b>(opcional): Se for <b>true</b>, a assinatura será aplicada em todas as páginas do documento. <br/>", responses = {
                    @ApiResponse(responseCode = "200", description = "Documento assinado com sucesso", content = @Content(mediaType = "application/pdf")),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido", content = @Content(mediaType = "application/json", schema = @Schema(implementation = String[].class))),
                    @ApiResponse(responseCode = "401", description = "Senha do certificado é inválida", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
                    @ApiResponse(responseCode = "403", description = "Certificado inválido", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            })
    public ResponseEntity<?> sign(
            @RequestParam(required = false) @NotNull MultipartFile file,
            @RequestParam(required = false) @NotNull MultipartFile certificate,
            @RequestParam(required = false) @NotNull @NotEmpty String password,
            @RequestParam(required = false) String url,
            @RequestParam(required = false) Integer pageIndex,
            @RequestParam(required = false) Integer x,
            @RequestParam(required = false) Integer y,
            @RequestParam(required = false, defaultValue = "false") Boolean allPages

    ) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);
        var certificatePath = this.fileUtils.uploadFile(certificate, FileLocationEnum.UPLOAD);
        Path outputPath = null;

        try {
            var visualSignatureConfig = new VisualSignatureConfig(pageIndex, x, y, allPages);
            var customCertificate = new CustomCertificate(certificatePath, password);

            byte[] signedDocument = this.signatureService.signDocument(filePath, customCertificate);
            outputPath = this.signatureFileService.createPDF(filePath, signedDocument, customCertificate,
                    visualSignatureConfig, url);

            var signedPdfData = Files.readAllBytes(outputPath);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION,
                    "attachment; filename=signed_" + file.getOriginalFilename());

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
    @Operation(summary = "Validar assinatura", description = "Valida se todas as assinaturas de um documento são válidas", responses = {
            @ApiResponse(responseCode = "200", description = "A assinatura é valida", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String[].class)))
    })
    public ResponseEntity<String> validateSignature(
            @RequestParam(required = false) @NotNull MultipartFile file) throws IOException {
        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);

        try {
            List<SignatureInformations> results = this.signatureValidationService
                    .validateAllSignatures(filePath);

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
    @Operation(summary = "Validar certificado", description = "Valida se um certificado é valido", responses = {
            @ApiResponse(responseCode = "200", description = "O certificado é valido", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido", content = @Content(mediaType = "application/json", schema = @Schema(implementation = String[].class))),
            @ApiResponse(responseCode = "401", description = "A senha ou certificado é inválido", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class)))
    })
    public ResponseEntity<String> validateCertificate(
            @RequestParam(required = false) @NotNull MultipartFile certificate,
            @RequestParam(required = false) @NotNull @NotEmpty String password) throws IOException {
        var certificatePath = this.fileUtils.uploadFile(certificate, FileLocationEnum.UPLOAD);

        try {
            var customCertificate = new CustomCertificate(certificatePath, password);
            customCertificate.checkValidity();
            return ResponseEntity.ok("Valid certificate");
        } catch (WrongCertificatePasswordException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid certificate");
        } finally {
            this.fileUtils.removeFile(certificatePath);
        }
    }

    @GetMapping("/qr-code")
    @Operation(summary = "Url na qual os Qr Codes apontam", description = "Caso lido pela câmera do celular, redireciona o usuário para o site <b>validar.iti.gov.br</b>. <br/>"
            +
            "Caso lido pelo validador do site, retorna um json com a URL do pdf, para o site realizar o download do arquivo. <br/><br/>"
            +
            "<b>_format</b> e <b>_secretCode</b> são parâmetros criados para utilização do validador do governo", responses = {
                    @ApiResponse(responseCode = "200", description = "Json com url do documento", content = @Content(mediaType = "application/json")),
                    @ApiResponse(responseCode = "303", description = "Redirecionamento para validar.iti.gov.br", content = @Content(mediaType = "")),
                    @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido", content = @Content(mediaType = "application/json", schema = @Schema(implementation = String[].class))),
            })
    public ResponseEntity<String> qrCode(
            @RequestParam(value = "_format", required = false) String format,
            @RequestParam(value = "_secretCode", required = false) String secretCode,
            @RequestParam(value = "url", required = false) @NotNull @NotEmpty String returnUrl)
            throws URISyntaxException, JsonProcessingException {
        if (Objects.equals(format, "application/validador-iti json")) {
            var result = new Object() {
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

    // =========================================================================
    // Assinatura XML — suporta A1 (síncrono) e NeoID (assíncrono)
    // =========================================================================

    @PostMapping(path = "/sign-xml", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Assina um arquivo XML",
            description = "Realiza a assinatura digital de um documento XML. "
                    + "O parâmetro <b>signatureType</b> define o provedor: "
                    + "<b>A1</b> (certificado do servidor, resposta síncrona), "
                    + "<b>NEOID</b> (certificado A3 em nuvem via SerproID, assíncrono) ou "
                    + "<b>SAFEID</b> (certificado A3 em nuvem via Safeweb PSC, assíncrono com PKCE). "
                    + "Para NEOID/SAFEID, a resposta 202 conterá o <b>jobId</b> e a <b>authorizationUrl</b>. "
                    + "Após a aprovação, use <b>GET /sign/status/{jobId}</b> para verificar "
                    + "e <b>GET /sign/download/{jobId}</b> para baixar o documento assinado. "
                    + "<br/><br/>Parâmetros opcionais para SafeID: "
                    + "<b>webhookUrl</b> (nossa API notifica via POST ao concluir) e "
                    + "<b>returnUrl</b> (nossa API redireciona o navegador ao concluir o callback).",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Documento XML assinado (A1 — síncrono)",
                            content = @Content(mediaType = "application/xml")),
                    @ApiResponse(responseCode = "202", description = "Assinatura assíncrona iniciada — aguardando aprovação do titular",
                            content = @Content(mediaType = "application/json")),
                    @ApiResponse(responseCode = "400", description = "Nó XML especificado não encontrado",
                            content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
                    @ApiResponse(responseCode = "401", description = "Certificado ou senha inválidos",
                            content = @Content(mediaType = "application/json", schema = @Schema(implementation = String[].class)))
            })
    public ResponseEntity<?> signXml(
            @RequestParam @NotNull MultipartFile file,
            @RequestParam(required = false) MultipartFile certificate,
            @RequestParam(required = false) String password,
            @RequestParam(required = false, defaultValue = "A1") SignatureType signatureType,
            @RequestParam(required = false, defaultValue = "false") boolean timeStamp,
            @RequestParam(required = false) String targetXPath,
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String webhookUrl,
            @RequestParam(required = false) String returnUrl) throws IOException {

        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);
        Path certificatePath = null;

        try {
            CustomCertificate customCertificate = null;
            if (signatureType == SignatureType.A1) {
                if (certificate == null || password == null) {
                    return ResponseEntity.badRequest()
                            .body("Para signatureType=A1, os campos 'certificate' e 'password' são obrigatórios.");
                }
                certificatePath = this.fileUtils.uploadFile(certificate, FileLocationEnum.UPLOAD);
                customCertificate = new CustomCertificate(certificatePath, password);
                customCertificate.checkValidity();
            }

            // Early validation of targetXPath — falha rápido antes de qualquer I/O de rede
            if (targetXPath != null && !targetXPath.isBlank()) {
                validateXPathExistsInFile(filePath, targetXPath);
            }

            var command = new SignXmlCommand(
                    filePath,
                    file.getOriginalFilename(),
                    customCertificate,
                    timeStamp,
                    targetXPath,
                    userId,
                    webhookUrl,
                    returnUrl
            );

            SignatureResult result = signatureStrategyResolver.resolve(signatureType).signXml(command);

            if (result instanceof SignatureResult.Completed c) {
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=" + file.getOriginalFilename())
                        .body(c.document());
            } else {
                SignatureResult.Pending p = (SignatureResult.Pending) result;
                String providerName = signatureType == SignatureType.SAFEID ? "SafeID" : "NeoID";
                String statusPath = "/api/v1/sign/status/" + p.jobId();
                return ResponseEntity.accepted()
                        .body(Map.of(
                                "jobId", p.jobId().toString(),
                                "authorizationUrl", p.authorizationUrl(),
                                "message", "Abra o link no aplicativo " + providerName
                                        + " para aprovar a assinatura. "
                                        + "Consulte o status em GET " + statusPath
                        ));
            }

        } catch (XmlNodeNotFoundException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (WrongCertificatePasswordException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } finally {
            this.fileUtils.removeFile(certificatePath);
            // filePath NÃO é removido para NeoID/SafeID — o orchestrator ainda precisa dele.
            if (signatureType == SignatureType.A1) {
                this.fileUtils.removeFile(filePath);
            }
        }
    }

    @PostMapping(path = "/validate-xml-signature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Validar assinatura de xml", description = "Valida se um documento xml está assinado", responses = {
            @ApiResponse(responseCode = "200", description = "A assinatura é valida", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Algum dado enviado é invalido", content = @Content(mediaType = "text/plain", schema = @Schema(implementation = String[].class)))
    })
    public ResponseEntity<String> validateXmlSignature(
            @RequestParam("file") MultipartFile file) throws IOException {

        var filePath = this.fileUtils.uploadFile(file, FileLocationEnum.UPLOAD);

        try {
            var isValid = this.signatureValidationService.validateXmlSignature(filePath);

            var responseMessage = isValid ? "Signed document XML" : "Unsigned document XML";
            return ResponseEntity.ok(responseMessage);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("File upload failed: " + e.getMessage());
        } finally {
            this.fileUtils.removeFile(filePath);
        }
    }

    // =========================================================================
    // Helpers privados
    // =========================================================================

    /**
     * Valida que o XPath aponta para um nó existente no arquivo XML dado.
     * Lança {@link XmlNodeNotFoundException} se não encontrado.
     */
    private void validateXPathExistsInFile(Path filePath, String targetXPath) throws Exception {
        var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        // Desativa acesso a entidades externas (prevenção de XXE)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        var doc = factory.newDocumentBuilder().parse(filePath.toFile());
        xmlNodeLocator.locate(doc, targetXPath);
    }

    // =========================================================================
    // Endpoints NeoID — Callback, Status e Download
    // =========================================================================

    @GetMapping("/neoid/callback")
    @Operation(
            summary = "Callback OAuth2 do NeoID",
            description = "Endpoint chamado pelo Serpro após aprovação do titular no aplicativo NeoID. "
                    + "Processa o <b>authorization_code</b>, obtém o <b>access_token</b>, "
                    + "envia o hash do documento para assinatura e salva o arquivo assinado. "
                    + "<br/><b>Não deve ser chamado diretamente pelo cliente — é exclusivo para o Serpro.</b>",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Assinatura processada com sucesso"),
                    @ApiResponse(responseCode = "502", description = "Falha na comunicação com o Serpro NeoID")
            })
    public ResponseEntity<String> neoIdCallback(
            @RequestParam String code,
            @RequestParam UUID state) {

        neoIdCallbackOrchestrator.process(code, state);
        return ResponseEntity.ok(
                "Assinatura aprovada e processada com sucesso. Você pode fechar esta janela.");
    }

    // =========================================================================
    // Endpoints SafeID — Callback
    // =========================================================================

    @GetMapping("/safeid/callback")
    @Operation(
            summary = "Callback OAuth2 do SafeID",
            description = "Endpoint chamado pelo SafeID (Safeweb PSC) após aprovação do titular. "
                    + "Processa o <b>authorization_code</b> com PKCE, obtém o <b>access_token</b>, "
                    + "envia o hash do documento para assinatura e salva o arquivo assinado. "
                    + "<br/>Se uma <b>returnUrl</b> foi informada ao iniciar a assinatura, redireciona o navegador. "
                    + "<br/><b>Não deve ser chamado diretamente pelo cliente — é exclusivo para o SafeID PSC.</b>",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Assinatura processada com sucesso"),
                    @ApiResponse(responseCode = "302", description = "Redirecionamento para returnUrl após processamento"),
                    @ApiResponse(responseCode = "400", description = "Usuário recusou a assinatura (error=user_denied)"),
                    @ApiResponse(responseCode = "502", description = "Falha na comunicação com o SafeID")
            })
    public ResponseEntity<?> safeIdCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam String state) throws java.net.URISyntaxException {

        UUID jobId = UUID.fromString(state);

        // Caso o usuário recuse a assinatura no app SafeID
        if (error != null && error.equals("user_denied")) {
            var job = signatureJobRepository.findById(jobId);
            if (job.isPresent() && job.get().isPending()) {
                job.get().fail("Assinatura recusada pelo titular no aplicativo SafeID");
                signatureJobRepository.save(job.get());
            }
            String returnUrl = job.map(j -> j.getReturnUrl()).orElse(null);
            if (returnUrl != null) {
                HttpHeaders headers = new HttpHeaders();
                headers.setLocation(new java.net.URI(returnUrl + "?jobId=" + jobId + "&status=FAILED&reason=user_denied"));
                return new ResponseEntity<>(headers, HttpStatus.FOUND);
            }
            return ResponseEntity.badRequest().body("Assinatura recusada pelo titular.");
        }

        String returnUrl = safeIdCallbackOrchestrator.process(code, jobId);

        // Redireciona o navegador se houver returnUrl configurada
        if (returnUrl != null && !returnUrl.isBlank()) {
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(new java.net.URI(returnUrl + "?jobId=" + jobId + "&status=COMPLETED"));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        return ResponseEntity.ok("Assinatura SafeID processada com sucesso. Você pode fechar esta janela.");
    }

    @GetMapping("/sign/status/{jobId}")
    @Operation(
            summary = "Status da assinatura NeoID",
            description = "Retorna o status atual de um job de assinatura via NeoID. "
                    + "Possíveis valores: <b>PENDING</b>, <b>COMPLETED</b>, <b>FAILED</b>, <b>EXPIRED</b>. "
                    + "Quando COMPLETED, inclui a URL de download do documento assinado.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Status retornado com sucesso",
                            content = @Content(mediaType = "application/json")),
                    @ApiResponse(responseCode = "404", description = "Job não encontrado")
            })
    public ResponseEntity<?> signatureStatus(@PathVariable UUID jobId) {
        var job = signatureJobRepository.findById(jobId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Job não encontrado: " + jobId));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jobId", job.getId().toString());
        response.put("status", job.getStatus().name());
        response.put("createdAt", job.getCreatedAt().toString());
        response.put("expiresAt", job.getExpiresAt().toString());

        if (job.isCompleted()) {
            response.put("completedAt", job.getCompletedAt().toString());
            response.put("downloadUrl", "/api/v1/sign/download/" + jobId);
        }

        if (job.getStatus() == JobStatus.FAILED) {
            response.put("errorMessage", job.getErrorMessage());
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/sign/download/{jobId}")
    @Operation(
            summary = "Download do documento assinado via NeoID",
            description = "Retorna o arquivo XML assinado de um job com status <b>COMPLETED</b>.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Arquivo XML assinado",
                            content = @Content(mediaType = "application/xml")),
                    @ApiResponse(responseCode = "404", description = "Job não encontrado ou ainda não concluído")
            })
    public ResponseEntity<byte[]> downloadSigned(@PathVariable UUID jobId) throws IOException {
        var job = signatureJobRepository.findById(jobId)
                .filter(j -> j.getStatus() == JobStatus.COMPLETED)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Job não encontrado ou ainda não concluído: " + jobId));

        byte[] content = Files.readAllBytes(Path.of(job.getSignedFilePath()));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=" + job.getSignedFileName())
                .contentType(MediaType.APPLICATION_XML)
                .body(content);
    }
}
