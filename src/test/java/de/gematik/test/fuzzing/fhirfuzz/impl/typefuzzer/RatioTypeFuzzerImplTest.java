/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.RatioTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Quantity;
import org.hl7.fhir.r4.model.Ratio;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RatioTypeFuzzerImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static RatioTypeFuzzerImpl typeFuzzer;
    private Ratio ratio;

    private static final String TESTSTRING = "Teststring";

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        typeFuzzer = new RatioTypeFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        ratio = new Ratio();
    }


    @Test
    void generateRandom() {
        assertNotNull(typeFuzzer.generateRandom());
    }

    @Test
    void getContext() {
        assertNotNull(typeFuzzer.getContext());
    }

    @Test
    void shouldFuzzNominator() {
        assertFalse(ratio.hasNumerator());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasNumerator());
        typeFuzzer.fuzz(ratio);
        assertFalse(ratio.hasNumerator());
        val testObject = new Quantity(fuzzerContext.getRandom().nextInt());
        ratio.setNumerator(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertNotEquals(testObject, ratio.getNumerator());

    }

    @Test
    void shouldFuzzDenom() {
        assertFalse(ratio.hasDenominator());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasDenominator());
        typeFuzzer.fuzz(ratio);
        assertFalse(ratio.hasDenominator());
        val testObject = new Quantity(fuzzerContext.getRandom().nextInt());
        ratio.setDenominator(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertNotEquals(testObject, ratio.getDenominator());
    }

    @Test
    void shouldFuzzId() {
        assertFalse(ratio.hasId());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasId());
        typeFuzzer.fuzz(ratio);
        val testObject = fuzzerContext.getIdFuzzer().generateRandom();
        ratio.setId(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertNotEquals(testObject, ratio.getId());

    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(ratio.hasExtension());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasExtension());
        typeFuzzer.fuzz(ratio);
        assertFalse(ratio.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        ratio.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertNotEquals(ext.getUrl(), ratio.getExtension().get(0).getUrl());
    }

    @Test
    void shouldFuzzNumeratorCode() {
        ratio.setNumerator(new Quantity(2));
        assertFalse(ratio.getNumerator().hasCode());
        ratio.getNumerator().setCode(TESTSTRING);
        assertTrue(ratio.getNumerator().hasCode());
        typeFuzzer.fuzz(ratio);
        assertFalse(ratio.getNumerator().hasCode());
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.getNumerator().hasCode());
    }

    @Test
    void shouldFuzzNumeratorSystem() {
        ratio.setNumerator(new Quantity(2));
        assertFalse(ratio.getNumerator().hasSystem());
        ratio.getNumerator().setSystem(TESTSTRING);
        assertTrue(ratio.getNumerator().hasSystem());
        ratio.getNumerator().setSystem(TESTSTRING);
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.getNumerator().hasSystem());
    }

    @Test
    void shouldFuzzNumeratorUnit() {
        ratio.setNumerator(new Quantity(2));
        assertFalse(ratio.getNumerator().hasUnit());
        ratio.getNumerator().setUnit(TESTSTRING);
        assertTrue(ratio.getNumerator().hasUnit());
        ratio.getNumerator().setUnit(TESTSTRING);
        fuzzConfig.setPercentOfAll(0.00f);
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.getNumerator().hasUnit());
    }

    @Test
    void shouldFuzzDenomCode() {
        ratio.setDenominator(new Quantity(5));
        assertFalse(ratio.getDenominator().hasCode());
        ratio.getDenominator().setCode(TESTSTRING);
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasExtension());
    }

    @Test
    void shouldFuzzDenomSystem() {
        ratio.setDenominator(new Quantity(5));
        assertFalse(ratio.hasExtension());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasExtension());
    }

    @Test
    void shouldFuzzDenomUnit() {
        ratio.setDenominator(new Quantity(5));
        assertFalse(ratio.hasExtension());
        typeFuzzer.fuzz(ratio);
        assertTrue(ratio.hasExtension());
    }

}