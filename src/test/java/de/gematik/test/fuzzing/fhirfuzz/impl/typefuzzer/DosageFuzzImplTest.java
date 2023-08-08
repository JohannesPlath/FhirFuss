/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodeableConceptFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.DosageFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.RatioTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.SimpleQuantityImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Dosage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class DosageFuzzImplTest {


    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static DosageFuzzImpl dosageFuzzImpl;

    private Dosage dosage;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        dosageFuzzImpl = new DosageFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        dosage = new Dosage();
    }

    @Test
    void shouldFuzzSequence() {
        assertFalse(dosage.hasSequence());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasSequence());
        val testObject = fuzzerContext.getRandom().nextInt();
        dosage.setSequence(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject, dosage.getSequence());
    }

    @Test
    void shouldFuzzText() {
        assertFalse(dosage.hasText());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasText());
        val testObject = fuzzerContext.getStringFuzz().generateRandom(100);
        dosage.setText(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject, dosage.getText());
    }

    @Test
    void shouldFuzzAdditionalInstr() {
        assertFalse(dosage.hasAdditionalInstruction());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasAdditionalInstruction());
        val testObject = new CodeableConceptFuzzer(fuzzerContext).generateRandom();
        dosage.setAdditionalInstruction(List.of(testObject.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject, dosage.getAdditionalInstructionFirstRep());
    }

    @Test
    void shouldFuzzPatientInstr() {
        assertFalse(dosage.hasPatientInstruction());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasPatientInstruction());
        val testObject = fuzzerContext.getStringFuzz().generateRandom(100);
        dosage.setPatientInstruction(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject, dosage.getPatientInstruction());
    }

    @Test
    void shouldFuzzSite() {
        assertFalse(dosage.hasSite());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasSite());
        val testObject = new CodeableConceptFuzzer(fuzzerContext).generateRandom();
        dosage.setSite(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getCodingFirstRep(), dosage.getSite().getCodingFirstRep());
    }

    @Test
    void shouldFuzzRoute() {
        assertFalse(dosage.hasRoute());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasRoute());
        val testObject = new CodeableConceptFuzzer(fuzzerContext).generateRandom();
        dosage.setRoute(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getCodingFirstRep(), dosage.getRoute().getCodingFirstRep());
    }

    @Test
    void shouldFuzzMethod() {
        assertFalse(dosage.hasMethod());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasMethod());
        val testObject = new CodeableConceptFuzzer(fuzzerContext).generateRandom();
        dosage.setMethod(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getCodingFirstRep(), dosage.getMethod().getCodingFirstRep());
    }

    @Test
    void shouldFuzzMaxDosePeriod() {
        assertFalse(dosage.hasMaxDosePerPeriod());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasMaxDosePerPeriod());
        val testObject = new RatioTypeFuzzerImpl(fuzzerContext).generateRandom();
        dosage.setMaxDosePerPeriod(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getNumerator(), dosage.getMaxDosePerPeriod().getNumerator());
    }

    @Test
    void shouldFuzzMaxDosePerAdmin() {
        assertFalse(dosage.hasMaxDosePerAdministration());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasMaxDosePerAdministration());
        val testObject = new SimpleQuantityImpl(fuzzerContext).generateRandom();
        dosage.setMaxDosePerAdministration(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getSystem(), dosage.getMaxDosePerAdministration().getSystem());
    }

    @Test
    void shouldFuzzMaxDPerLifetime() {
        assertFalse(dosage.hasMaxDosePerLifetime());
        dosageFuzzImpl.fuzz(dosage);
        Assertions.assertTrue(dosage.hasMaxDosePerLifetime());
        val testObject = new SimpleQuantityImpl(fuzzerContext).generateRandom();
        dosage.setMaxDosePerLifetime(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        dosageFuzzImpl.fuzz(dosage);
        assertNotEquals(testObject.getSystem(), dosage.getMaxDosePerLifetime().getSystem());
    }


    @Test
    void generateRandom() {
        assertTrue(dosageFuzzImpl.generateRandom().hasText());
    }

    @Test
    void getContext() {
        assertNotNull(dosageFuzzImpl.getContext().getFuzzConfig().getPercentOfEach());
    }
}