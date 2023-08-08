/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.PeriodFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ReferenceFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Coverage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoverageFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static CoverageFuzzImpl coverageFuzz;
    private Coverage coverage;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        coverageFuzz = new CoverageFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        coverage = new Coverage();
    }

    @Test
    void shouldFuzzId() {
        assertFalse(coverage.hasId());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasId());
        coverageFuzz.fuzz(coverage);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        coverage.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(teststring, coverage.getId());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(coverage.hasMeta());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasMeta());
        coverageFuzz.fuzz(coverage);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        coverage.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(meta.getProfile(), coverage.getMeta().getProfile());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(coverage.hasExtension());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasExtension());
        coverageFuzz.fuzz(coverage);
        assertFalse(coverage.hasExtension());

    }

    @Test
    void shouldFuzzStatus() {
        assertFalse(coverage.hasStatus());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasStatus());
        fuzzConfig.setPercentOfAll(100.00f);
        coverageFuzz.fuzz(coverage);
        val status = fuzzerContext.getRandomOneOfClass(Coverage.CoverageStatus.class, List.of(Coverage.CoverageStatus.NULL));
        coverage.setStatus(status);
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(status, coverage.getStatus());
    }


    @Test
    void shouldFuzzBeneficiary() {
        assertFalse(coverage.hasBeneficiary());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasBeneficiary());
        fuzzConfig.setPercentOfAll(100.00f);
        coverageFuzz.fuzz(coverage);
        val referenceFuzz = new ReferenceFuzzerImpl(fuzzerContext);
        val type = referenceFuzz.generateRandom();
        coverage.setBeneficiary(type.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(type.getReference(), coverage.getBeneficiary().getReference());
    }

    @Test
    void shouldFuzzPeriod() {
        assertFalse(coverage.hasPeriod());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasPeriod());
        fuzzConfig.setPercentOfAll(100.00f);
        coverageFuzz.fuzz(coverage);
        val period = new PeriodFuzzerImpl(fuzzerContext).generateRandom();
        coverage.setPeriod(period.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(period, coverage.getPeriod());
    }

    @Test
    void shouldFuzzPayor() {
        assertFalse(coverage.hasPayor());
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasPayor());
        fuzzConfig.setPercentOfAll(100.00f);
        coverageFuzz.fuzz(coverage);
        val referenceFuzz = new ReferenceFuzzerImpl(fuzzerContext);
        val type = referenceFuzz.generateRandom();
        coverage.setPayor(List.of(type.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(type.getReference(), coverage.getPayorFirstRep().getReference());
    }

    @Test
    void shouldAcceptDetailSetup() {
        fuzzerContext.getFuzzConfig().setDetailSetup(new HashMap<>());
        fuzzerContext.getFuzzConfig().getDetailSetup().put("KBV", "TRUE");
        assertFalse(coverage.hasPayor());
        coverageFuzz.fuzz(coverage);
        assertFalse(coverage.hasPayor());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("KBV");
        coverageFuzz.fuzz(coverage);
        assertTrue(coverage.hasPayor());
        fuzzConfig.setPercentOfAll(100.00f);
        coverageFuzz.fuzz(coverage);
        val referenceFuzz = new ReferenceFuzzerImpl(fuzzerContext);
        val type = referenceFuzz.generateRandom();
        coverage.setPayor(List.of(type.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        coverageFuzz.fuzz(coverage);
        assertNotEquals(type.getReference(), coverage.getPayorFirstRep().getReference());
    }

    @Test
    void generateRandom() {
        assertTrue(coverageFuzz.generateRandom().hasStatus());
    }

    @Test
    void getContext() {
        assertNotNull(coverageFuzz.getContext());
    }
}