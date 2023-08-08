/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.SimpleQuantityImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Quantity;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimpleQuantityImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static SimpleQuantityImpl quantityFuzzer;
    private Quantity quantity;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        quantityFuzzer = new SimpleQuantityImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        quantity = new Quantity();
    }

    @Test
    void shouldFuzzUnit() {
        assertFalse(quantity.hasUnit());
        quantityFuzzer.fuzz(quantity);
        assertTrue(quantity.hasUnit());
        quantityFuzzer.fuzz(quantity);
        val testObject = fuzzerContext.getStringFuzz().generateRandom(15);
        quantity.setUnit(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        quantityFuzzer.fuzz(quantity);
        assertNotEquals(testObject, quantity.getUnit());
    }

    @Test
    void shouldFuzzSystem() {
        assertFalse(quantity.hasSystem());
        quantityFuzzer.fuzz(quantity);
        assertTrue(quantity.hasSystem());
        quantityFuzzer.fuzz(quantity);
        val testObject = fuzzerContext.getStringFuzz().generateRandom(15);
        quantity.setSystem(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        quantityFuzzer.fuzz(quantity);
        assertNotEquals(testObject, quantity.getSystem());
    }

    @Test
    void shouldFuzzValue() {
        assertFalse(quantity.hasValue());
        quantityFuzzer.fuzz(quantity);
        assertTrue(quantity.hasValue());
        quantityFuzzer.fuzz(quantity);
        val testObject = fuzzerContext.getIntFuzz().generateRandom();
        quantity.setValue(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        quantityFuzzer.fuzz(quantity);
        assertNotEquals(testObject, quantity.getValue());
    }

    @Test
    void shouldFuzzCode() {
        assertFalse(quantity.hasCode());
        quantityFuzzer.fuzz(quantity);
        assertTrue(quantity.hasCode());
        quantityFuzzer.fuzz(quantity);
        val testObject = fuzzerContext.getStringFuzz().generateRandom(15);
        quantity.setCode(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        quantityFuzzer.fuzz(quantity);
        assertNotEquals(testObject, quantity.getCode());
    }


    @Test
    void generateRandom() {
        assertNotNull(quantityFuzzer.generateRandom().getValue());
    }

    @Test
    void getContext() {
        assertNotNull(quantityFuzzer.getContext());
    }
}