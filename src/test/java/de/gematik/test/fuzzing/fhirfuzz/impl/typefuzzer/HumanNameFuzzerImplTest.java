/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.HumanNameFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.PeriodFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.Period;
import org.hl7.fhir.r4.model.StringType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HumanNameFuzzerImplTest {

    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static HumanNameFuzzerImpl nameFuzzer;

    private HumanName humanName;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        nameFuzzer = new HumanNameFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setUseAllMutators(true);
        humanName = new HumanName();
    }

    @Test
    void shouldFuzzUse() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasUse());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasUse());
        fuzzConfig.setPercentOfAll(00.0f);
        humanName.setUse(HumanName.NameUse.NICKNAME);
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasUse());
        assertNotEquals(HumanName.NameUse.NICKNAME, humanName.getUse());
    }

    @Test
    void shouldFuzzText() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasText());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasText());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getStringFuzz().generateRandom(150);
        humanName.setText(text);
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasText());
        assertNotEquals(text, humanName.getText());
    }

    @Test
    void shouldFuzzFamily() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasFamily());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasFamily());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getStringFuzz().generateRandom(150);
        humanName.setFamily(text);
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasFamily());
        assertNotEquals(text, humanName.getFamily());
    }

    @Test
    void shouldFuzzGiven() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasGiven());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasGiven());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getStringFuzz().generateRandom(150);
        humanName.setGiven(List.of(new StringType(text)));
        assertEquals(text, humanName.getGiven().get(0).toString());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasGiven());
        assertNotEquals(text, humanName.getGiven().get(0).toString());
    }

    @Test
    void shouldFuzzPrefix() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasPrefix());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasPrefix());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getStringFuzz().generateRandom(150);
        humanName.setPrefix(List.of(new StringType(text)));
        assertEquals(text, humanName.getPrefixAsSingleString());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasPrefix());
        assertNotEquals(text, humanName.getPrefixAsSingleString());
    }

    @Test
    void shouldFuzzSuffix() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasSuffix());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasSuffix());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        val text = fuzzerContext.getStringFuzz().generateRandom(150);
        humanName.setSuffix(List.of(new StringType(text)));
        assertEquals(text, humanName.getSuffixAsSingleString());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasSuffix());
        assertNotEquals(text, humanName.getSuffixAsSingleString());
    }

    @Test
    void shouldFuzzPeriod() {
        fuzzConfig.setPercentOfAll(00.0f);
        assertFalse(humanName.hasPeriod());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasPeriod());
        fuzzConfig.setPercentOfAll(100.0f);
        nameFuzzer.fuzz(humanName);
        fuzzConfig.setPercentOfAll(00.0f);
        Period period = new PeriodFuzzerImpl(fuzzerContext).generateRandom();
        humanName.setPeriod(period.copy());
        nameFuzzer.fuzz(humanName);
        assertTrue(humanName.hasPeriod());
        assertNotEquals(period.getStartElement().getMillis(), humanName.getPeriod().getStartElement().getMillis());
    }

    @Test
    void getContext() {
        assertNotNull(nameFuzzer.getContext());
    }

    @Test
    void generateRandom() {
        assertNotNull(nameFuzzer.generateRandom().getFamily());
    }
}