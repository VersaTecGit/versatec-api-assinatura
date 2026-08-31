package com.versatec.signature.strategy;

import com.versatec.domain.SignatureType;
import com.versatec.services.SignatureService;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;
import org.springframework.stereotype.Component;

/**
 * Estratégia de assinatura via <b>Certificado A1</b> residente no servidor.
 * <p>
 * Delega inteiramente para o {@link SignatureService} existente, sem modificá-lo.
 * O fluxo é <b>síncrono</b>: a assinatura é realizada e o documento retornado
 * na mesma requisição HTTP.
 * <p>
 * <b>Retrocompatibilidade garantida</b>: esta estratégia é o comportamento padrão
 * quando o cliente não informa {@code signatureType} na requisição.
 */
@Component
public class A1SignatureStrategy implements SignatureStrategy {

    private final SignatureService signatureService;

    public A1SignatureStrategy(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    /**
     * Assina o XML usando o certificado A1 informado no command e retorna
     * o documento assinado imediatamente (fluxo síncrono).
     *
     * @param command deve ter {@code certificate} preenchido (não null)
     * @return {@link SignatureResult.Completed} com o XML assinado em bytes
     */
    @Override
    public SignatureResult signXml(SignXmlCommand command) throws Exception {
        byte[] signedDocument = signatureService.signXmlDocument(
                command.filePath(),
                command.certificate(),
                command.timeStamp(),
                command.targetXPath()
        );

        return new SignatureResult.Completed(signedDocument, command.originalFileName());
    }

    @Override
    public SignatureType supports() {
        return SignatureType.A1;
    }
}
