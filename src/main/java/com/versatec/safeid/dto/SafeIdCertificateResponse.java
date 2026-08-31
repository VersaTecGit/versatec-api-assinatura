package com.versatec.safeid.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Resposta do endpoint {@code GET /oauth/certificate/info} do SafeID.
 */
public record SafeIdCertificateResponse(
        @JsonProperty("certificates") List<CertificateData> certificates
) {
    public record CertificateData(
            @JsonProperty("base64") String base64
    ) {}
}
