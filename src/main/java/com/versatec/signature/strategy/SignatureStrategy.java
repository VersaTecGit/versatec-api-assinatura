package com.versatec.signature.strategy;

import com.versatec.domain.SignatureType;
import com.versatec.signature.dto.SignXmlCommand;
import com.versatec.signature.dto.SignatureResult;

/**
 * Contrato do padrão Strategy para assinatura digital de documentos XML.
 * <p>
 * Cada implementação encapsula um provedor específico:
 * <ul>
 *   <li>{@link A1SignatureStrategy}    — certificado A1 residente no servidor (síncrono)</li>
 *   <li>{@link NeoIdSignatureStrategy} — certificado A3 em nuvem via NeoID/Serpro (assíncrono)</li>
 * </ul>
 *
 * <p><b>Como adicionar um novo provedor:</b>
 * <ol>
 *   <li>Adicionar o valor ao enum {@link SignatureType}.</li>
 *   <li>Criar uma classe {@code @Component} que implemente esta interface.</li>
 *   <li>Nenhuma outra classe precisa ser modificada — o {@link SignatureStrategyResolver}
 *       descobrirá a nova implementação automaticamente via injeção de dependência do Spring.</li>
 * </ol>
 */
public interface SignatureStrategy {

    /**
     * Executa ou inicia a assinatura de um documento XML.
     * <p>
     * Implementações síncronas (A1) retornam {@link SignatureResult.Completed} imediatamente.
     * Implementações assíncronas (NeoID) retornam {@link SignatureResult.Pending} com
     * o jobId e a URL de autorização OAuth2.
     *
     * @param command dados da requisição de assinatura
     * @return resultado discriminado da operação
     * @throws Exception em caso de falha na operação de assinatura
     */
    SignatureResult signXml(SignXmlCommand command) throws Exception;

    /**
     * Retorna o tipo de assinatura suportado por esta estratégia.
     * Usado pelo {@link SignatureStrategyResolver} para roteamento.
     */
    SignatureType supports();
}
