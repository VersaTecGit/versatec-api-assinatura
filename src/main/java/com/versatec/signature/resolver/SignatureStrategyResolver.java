package com.versatec.signature.resolver;

import com.versatec.domain.SignatureType;
import com.versatec.signature.strategy.SignatureStrategy;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Factory que resolve a {@link SignatureStrategy} correta em tempo de execução.
 * <p>
 * O Spring injeta automaticamente <b>todas</b> as implementações de
 * {@link SignatureStrategy} presentes no contexto. O resolver as indexa por
 * {@link SignatureType}, tornando o roteamento O(1) via {@code Map}.
 *
 * <p><b>Extensibilidade (Open/Closed Principle)</b>: para adicionar um novo
 * provedor, basta criar um novo {@code @Component} que implemente
 * {@link SignatureStrategy}. Este resolver não precisa ser modificado.
 *
 * <p><b>Exemplo de uso no controller:</b>
 * <pre>{@code
 * SignatureStrategy strategy = resolver.resolve(signatureType);
 * SignatureResult result = strategy.signXml(command);
 * }</pre>
 */
@Component
public class SignatureStrategyResolver {

    private final Map<SignatureType, SignatureStrategy> strategies;

    /**
     * Constrói o resolver indexando as estratégias por tipo suportado.
     *
     * @param strategyList todas as implementações de {@link SignatureStrategy}
     *                     injetadas automaticamente pelo Spring
     * @throws IllegalStateException se duas estratégias declararem o mesmo {@link SignatureType}
     */
    public SignatureStrategyResolver(List<SignatureStrategy> strategyList) {
        this.strategies = strategyList.stream()
                .collect(Collectors.toMap(
                        SignatureStrategy::supports,
                        Function.identity(),
                        (a, b) -> {
                            throw new IllegalStateException(
                                    "Conflito: duas estratégias declararam suporte ao mesmo tipo: "
                                            + a.supports());
                        }
                ));
    }

    /**
     * Retorna a estratégia registrada para o tipo informado.
     *
     * @param type tipo de assinatura desejado
     * @return a estratégia correspondente
     * @throws UnsupportedOperationException se nenhuma estratégia suportar o tipo
     */
    public SignatureStrategy resolve(SignatureType type) {
        SignatureStrategy strategy = strategies.get(type);
        if (strategy == null) {
            throw new UnsupportedOperationException(
                    "Tipo de assinatura não suportado: " + type
                            + ". Tipos disponíveis: " + strategies.keySet());
        }
        return strategy;
    }
}
