/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.NarrativeTypeFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Narrative;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NarrativeTypeFuzzerTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static NarrativeTypeFuzzer typeFuzzer;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        typeFuzzer = new NarrativeTypeFuzzer(fuzzerContext);
    }

    @Test
    void shouldFuzzStatus() {

        fuzzConfig.setPercentOfAll(00.0f);
        val nType = new Narrative();
        nType.setDiv(null);
        assertFalse(nType.hasStatus());
        typeFuzzer.fuzz(nType);
        assertTrue(nType.hasStatus());
        fuzzConfig.setPercentOfAll(100.0f);
        nType.setStatus(null);
        assertFalse(nType.hasStatus());
        fuzzConfig.setPercentOfAll(00.0f);
        val c = Narrative.NarrativeStatus.ADDITIONAL;
        nType.setStatus(c);
        typeFuzzer.fuzz(nType);
        assertTrue(nType.hasStatus());
        assertNotEquals(c, nType.getStatus());

    }

    @Test
    void shouldFuzzId() {

        fuzzConfig.setPercentOfAll(00.0f);
        val nType = new Narrative();
        nType.setId(null);
        assertFalse(nType.hasId());
        typeFuzzer.fuzz(nType);
        assertTrue(nType.hasId());
        fuzzConfig.setPercentOfAll(100.0f);
        nType.setId(null);
        assertFalse(nType.hasId());
        fuzzConfig.setPercentOfAll(00.0f);
        val c = fuzzerContext.getIdFuzzer().generateRandom();
        nType.setId(c);
        typeFuzzer.fuzz(nType);
        assertTrue(nType.hasId());
        assertNotEquals(c, nType.getId());

    }

    @Test
    void ShouldGenerateRandom() {
        assertNotNull(typeFuzzer.generateRandom());
    }

    @Test
    void shouldGetContext() {
        assertNotNull(typeFuzzer.getContext());
    }

}