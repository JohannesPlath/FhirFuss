/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.numberfuzzer;

import de.gematik.test.fuzzing.fhirfuzz.BaseFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;

public class IntFuzzImpl implements BaseFuzzer<Integer> {

    private final FuzzerContext fuzzerContext;

    public IntFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Integer fuzz(Integer value) {
        Integer result;
        do {
            result = fuzzerContext.getRandom().nextInt();
        } while (value.equals(result));
        return result;
    }

    @Override
    public Integer generateRandom() {
        return fuzzerContext.getRandom().nextInt();
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }
}
