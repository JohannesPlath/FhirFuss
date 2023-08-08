/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodingTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Medication;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MedicationFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static MedicationFuzzImpl medicationFuzz;
    private Medication medication;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setDetailSetup(new HashMap<>());
        fuzzerContext = new FuzzerContext(fuzzConfig);
        medicationFuzz = new MedicationFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        medication = new Medication();
    }


    @Test
    void generateRandom() {
        assertNotNull(medicationFuzz.generateRandom().getId());
    }

    @Test
    void getContext() {
        assertNotNull(medicationFuzz.getContext());
    }

    @Test
    void shouldFuzzId() {
        assertFalse(medication.hasId());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasId());
        medicationFuzz.fuzz(medication);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        medication.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(teststring, medication.getId());
    }

    @Test
    void shoulFuzzLanguage() {
        assertFalse(medication.hasLanguage());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasLanguage());
        medicationFuzz.fuzz(medication);
        val teststring = "123.345.5678";
        medication.setLanguage((teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(teststring, medication.getLanguage());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(medication.hasMeta());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasMeta());
        medicationFuzz.fuzz(medication);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        medication.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(meta.getProfile(), medication.getMeta().getProfile());
    }

    @Test
    void shouldFuzzIdentifier() {
        assertFalse(medication.hasIdentifier());
        medicationFuzz.fuzz(medication);
        medicationFuzz.fuzz(medication);
        assertFalse(medication.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        medication.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(input, medication.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldFuzzForm() {
        assertFalse(medication.hasForm());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasForm());
        fuzzConfig.setPercentOfAll(100.00f);
        medicationFuzz.fuzz(medication);
        CodingTypeFuzzerImpl codingTypeFuzzerImpl = new CodingTypeFuzzerImpl(fuzzerContext);
        val type = codingTypeFuzzerImpl.gerateRandomCodingConcept();
        medication.setForm(type.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(type.getCodingFirstRep(), medication.getForm().getCodingFirstRep());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(medication.hasExtension());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasExtension());
        medicationFuzz.fuzz(medication);
        assertFalse(medication.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        medication.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(ext.getValue(), medication.getExtension().get(0).getValue());
    }


    @Test
    void shouldFuzzCode() {
        assertFalse(medication.hasForm());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasForm());
        fuzzConfig.setPercentOfAll(100.00f);
        medicationFuzz.fuzz(medication);
        CodingTypeFuzzerImpl codingTypeFuzzerImpl = new CodingTypeFuzzerImpl(fuzzerContext);
        val type = codingTypeFuzzerImpl.gerateRandomCodingConcept();
        medication.setCode(type.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(type.getCodingFirstRep(), medication.getCode().getCodingFirstRep());
    }

    @Test
    void shouldFuzzStatus() {
        assertFalse(medication.hasStatus());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasStatus());
        fuzzConfig.setPercentOfAll(100.00f);
        medicationFuzz.fuzz(medication);
        val status = fuzzerContext.getRandomOneOfClass(Medication.MedicationStatus.class, List.of(Medication.MedicationStatus.NULL));
        medication.setStatus(status);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(status, medication.getStatus());
    }

    @Test
    void shouldAcceptDetailSetup() {
        fuzzerContext.getFuzzConfig().getDetailSetup().put("KBV", "TRUE");
        assertFalse(medication.hasIdentifier());
        medicationFuzz.fuzz(medication);
        assertFalse(medication.hasIdentifier());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("KBV");
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        medication.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationFuzz.fuzz(medication);
        assertNotEquals(input, medication.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldAcceptDetailSetupAndFuzzesCodeText() {
        assertFalse(medication.hasCode());
        medicationFuzz.fuzz(medication);
        assertTrue(medication.hasCode());
        medication.getCode().setText("123");
        assertFalse(medication.getCode().getText().length() > 50);
        fuzzerContext.getFuzzConfig().getDetailSetup().put("BreakRanges", "TRUE");
        medicationFuzz.fuzz(medication);
        assertTrue(medication.getCode().getText().length() > 50);
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("BreakRanges");

    }

    @Test
    void shouldFuzzAmount() {

    }
}