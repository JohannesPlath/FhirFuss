/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.PeriodFuzzerImpl;
import lombok.val;
import org.hl7.fhir.r4.model.Period;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeriodFuzzerImplTest {

    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static PeriodFuzzerImpl periodFuzzer;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        periodFuzzer = new PeriodFuzzerImpl(fuzzerContext);
    }

    @Test
    void shouldFuzzStart() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        Period period = new Period();
        assertFalse(period.hasStart());
        periodFuzzer.fuzz(period);
        assertTrue(period.hasStart());
        fuzzConfig.setPercentOfAll(100.0f);
        periodFuzzer.fuzz(period);
        assertFalse(period.hasStart());
        fuzzConfig.setPercentOfAll(00.0f);
        val start = fuzzerContext.getRandomDate();
        period.setStart(start);
        periodFuzzer.fuzz(period);
        assertTrue(period.hasStart());
        assertNotEquals(start, period.getStart());

    }

    @Test
    void shouldFuzzEnd() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        Period period = new Period();
        assertFalse(period.hasEnd());
        periodFuzzer.fuzz(period);
        assertTrue(period.hasEnd());
        fuzzConfig.setPercentOfAll(100.0f);
        periodFuzzer.fuzz(period);
        assertFalse(period.hasEnd());
        fuzzConfig.setPercentOfAll(00.0f);
        val end = fuzzerContext.getRandomDate();
        period.setEnd(new Date(end.getTime()));
        periodFuzzer.fuzz(period);
        assertTrue(period.hasEnd());
        assertNotEquals(end.getTime(), period.getEnd().getTime());
    }

}