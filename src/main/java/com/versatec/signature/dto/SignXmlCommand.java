package com.versatec.signature.dto;

import com.versatec.customs.CustomCertificate;

import java.nio.file.Path;

/**
 * Command object que encapsula todos os dados necessários para assinar um XML.
 * <p>
 * Funciona como o input unificado da interface {@link com.versatec.signature.strategy.SignatureStrategy}.
 * Cada estratégia utiliza apenas os campos que lhe são relevantes:
 * <ul>
 *   <li><b>A1</b>: usa {@code certificate} (obrigatório) e ignora {@code userId}, {@code webhookUrl}, {@code returnUrl}.</li>
 *   <li><b>NeoID</b>: ignora {@code certificate} e usa {@code userId} para rastreabilidade.</li>
 *   <li><b>SafeID</b>: ignora {@code certificate} e usa {@code userId}, {@code webhookUrl} e {@code returnUrl}.</li>
 * </ul>
 *
 * @param filePath         caminho do arquivo XML no servidor (temporário)
 * @param originalFileName nome original do arquivo enviado pelo cliente
 * @param certificate      certificado A1 carregado (null para NeoID/SafeID)
 * @param timeStamp        se true, aplica Carimbo do Tempo (TSA Serpro) — apenas para A1
 * @param targetXPath      nó XPath alvo da assinatura; null assina o documento inteiro
 * @param userId           identificador do solicitante (para rastreabilidade)
 * @param webhookUrl       URL de webhook para notificação assíncrona ao concluir o job (opcional)
 * @param returnUrl        URL de redirecionamento após o callback OAuth2 (opcional, para SPA/mobile)
 */
public record SignXmlCommand(
        Path filePath,
        String originalFileName,
        CustomCertificate certificate,
        boolean timeStamp,
        String targetXPath,
        String userId,
        String webhookUrl,
        String returnUrl
) {}

