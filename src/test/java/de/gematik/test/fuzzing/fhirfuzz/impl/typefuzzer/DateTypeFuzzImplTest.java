/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.DateTypeFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.DateType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DateTypeFuzzImplTest {

    static DateTypeFuzzImpl dateTypeFuzz;
    static FuzzerContext fuzzerContext;
    static FuzzConfig fuzzConfig;
    DateType dateType;

    @BeforeAll
    static void setupStatic() {
        fuzzConfig = new FuzzConfig();
        fuzzerContext = new FuzzerContext(fuzzConfig);
        dateTypeFuzz = new DateTypeFuzzImpl(fuzzerContext);
        fuzzConfig.setUseAllMutators(true);
    }

    @BeforeEach
    void setup() {
        fuzzConfig.setPercentOfAll(100f);
        fuzzConfig.setPercentOfEach(100f);
        dateType = new DateType();
    }

    @Test
    void getContext() {
        assertNotNull(dateTypeFuzz.getContext());
    }

    @Test
    void generateRandom() {
        assertNotNull(dateTypeFuzz.generateRandom());
    }

    @Test
    void shouldFuzzId() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(dateType.hasId());
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasId());
        fuzzConfig.setPercentOfAll(100.0f);
        dateTypeFuzz.fuzz(dateType);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getIdFuzzer().generateRandom();
        dateType.setId(text);
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasId());
        assertNotEquals(text, dateType.getId());
    }

    @Test
    void shouldFuzzExtension() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(dateType.hasExtension());
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasExtension());
        fuzzConfig.setPercentOfAll(100.0f);
        dateTypeFuzz.fuzz(dateType);
        assertFalse(dateType.hasExtension());
        fuzzConfig.setPercentOfAll(00.0f);
        val text = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        var testString = text.getUrl();
        dateType.setExtension(List.of(text));
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasExtension());
        assertNotEquals(testString, dateType.getExtension().get(0).getUrl());
    }


    @Test
    void shouldFuzzValue() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(dateType.hasValue());
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasValue());
        fuzzConfig.setPercentOfAll(100.0f);
        dateTypeFuzz.fuzz(dateType);
        assertFalse(dateType.hasValue());
        fuzzConfig.setPercentOfAll(00.0f);
        val date = fuzzerContext.getRandomDateWithFactor(5);
        var time = date.getTime();
        dateType.setValue(date);
        dateTypeFuzz.fuzz(dateType);
        assertTrue(dateType.hasValue());
        assertNotEquals(time, dateType.getValue().getTime());
    }
}