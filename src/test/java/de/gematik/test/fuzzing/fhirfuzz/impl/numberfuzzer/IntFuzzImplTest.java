/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.numberfuzzer;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntFuzzImplTest {

    private static FuzzerContext fuzzerContext;
    private static IntFuzzImpl intFuzz;
    private final int TESTITERATIONS = 10;

    @BeforeAll
    static void setUpConf() {
        val fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        val fuzzerContext = new FuzzerContext(fuzzConfig);
        intFuzz = new IntFuzzImpl(fuzzerContext);
    }

    @RepeatedTest(TESTITERATIONS)
    void fuzz() {
        val testObject = intFuzz.generateRandom();
        assertNotEquals(testObject, intFuzz.fuzz(testObject));
    }

    @Test
    void generateRandom() {
        assertNotNull(intFuzz.generateRandom());

    }

    @Test
    void getContext() {
        assertTrue(intFuzz.getContext().getFuzzConfig().getUseAllMutators());
    }
}