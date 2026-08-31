package com.versatec.signature.resolver;

import com.versatec.domain.SignatureType;
import com.versatec.signature.strategy.SignatureStrategy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SignatureStrategyResolverTest {

    private SignatureStrategy mockStrategy(SignatureType type) {
        SignatureStrategy s = mock(SignatureStrategy.class);
        when(s.supports()).thenReturn(type);
        return s;
    }

    @Test
    void resolve_A1_shouldReturnA1Strategy() {
        var a1 = mockStrategy(SignatureType.A1);
        var neoid = mockStrategy(SignatureType.NEOID);
        var resolver = new SignatureStrategyResolver(List.of(a1, neoid));

        SignatureStrategy result = resolver.resolve(SignatureType.A1);
        assertSame(a1, result);
    }

    @Test
    void resolve_NEOID_shouldReturnNeoIdStrategy() {
        var a1 = mockStrategy(SignatureType.A1);
        var neoid = mockStrategy(SignatureType.NEOID);
        var resolver = new SignatureStrategyResolver(List.of(a1, neoid));

        SignatureStrategy result = resolver.resolve(SignatureType.NEOID);
        assertSame(neoid, result);
    }

    @Test
    void resolve_unknownType_shouldThrowUnsupportedOperationException() {
        var a1 = mockStrategy(SignatureType.A1);
        var resolver = new SignatureStrategyResolver(List.of(a1));

        assertThrows(UnsupportedOperationException.class,
                () -> resolver.resolve(SignatureType.NEOID));
    }

    @Test
    void constructor_duplicateType_shouldThrowIllegalStateException() {
        var a1a = mockStrategy(SignatureType.A1);
        var a1b = mockStrategy(SignatureType.A1);

        assertThrows(IllegalStateException.class,
                () -> new SignatureStrategyResolver(List.of(a1a, a1b)));
    }
}
