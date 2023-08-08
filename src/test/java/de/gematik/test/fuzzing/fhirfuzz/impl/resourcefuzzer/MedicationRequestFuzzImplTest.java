/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AnnotationTypeFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.DosageFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ReferenceFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.SimpleQuantityImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.MedicationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MedicationRequestFuzzImplTest {

    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static MedicationRequestFuzzImpl medicationRequestFuzz;
    private MedicationRequest medicationRe;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        medicationRequestFuzz = new MedicationRequestFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        medicationRe = new MedicationRequest();
    }


    @Test
    void generateRandom() {
        assertNotNull(medicationRequestFuzz.generateRandom().getId());
    }

    @Test
    void getContext() {
        assertNotNull(medicationRequestFuzz.getContext());
    }


    @Test
    void shouldFuzzLanguage() {
        assertFalse(medicationRe.hasLanguage());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasLanguage());
        medicationRequestFuzz.fuzz(medicationRe);
        val teststring = "123.345.5678";
        medicationRe.setLanguage((teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(teststring, medicationRe.getLanguage());
    }

    @Test
    void shouldFuzzStatus() {
        assertFalse(medicationRe.hasStatus());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasStatus());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = fuzzerContext.getRandomOneOfClass(MedicationRequest.MedicationRequestStatus.class);
        medicationRe.setStatus((testObject));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject, medicationRe.getStatus());
    }

    @Test
    void shouldFuzzSubj() {
        assertFalse(medicationRe.hasSubject());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasSubject());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = new ReferenceFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setSubject(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject, medicationRe.getSubject());
    }

    @Test
    void shouldFuzzNote() {
        assertFalse(medicationRe.hasNote());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasNote());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = new AnnotationTypeFuzzImpl(fuzzerContext).generateRandom();
        medicationRe.setNote(List.of(testObject.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject.getText(), medicationRe.getNote().get(0).getText());
    }

    @Test
    void shouldFuzzInsurance() {
        assertFalse(medicationRe.hasInsurance());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasInsurance());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = new ReferenceFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setInsurance(List.of(testObject.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject.getReference(), medicationRe.getInsuranceFirstRep().getReference());
    }

    @Test
    void shouldFuzzRequester() {
        assertFalse(medicationRe.hasRequester());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasRequester());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = new ReferenceFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setRequester(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject, medicationRe.getRequester());
    }

    @Test
    void shouldFuzzMedication() {
        assertFalse(medicationRe.hasMedication());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasMedication());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = new ReferenceFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setMedication(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject, medicationRe.getMedication());
    }

    @Test
    void shouldFuzzIntend() {
        assertFalse(medicationRe.hasIntent());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasIntent());
        medicationRequestFuzz.fuzz(medicationRe);
        val testObject = fuzzerContext.getRandomOneOfClass(MedicationRequest.MedicationRequestIntent.class);
        medicationRe.setIntent((testObject));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(testObject, medicationRe.getIntent());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(medicationRe.hasMeta());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasMeta());
        medicationRequestFuzz.fuzz(medicationRe);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(meta.getProfile(), medicationRe.getMeta().getProfile());
    }

    @Test
    void shouldFuzzIdentifier() {
        assertFalse(medicationRe.hasIdentifier());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasIdentifier());
        medicationRequestFuzz.fuzz(medicationRe);
        assertFalse(medicationRe.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        medicationRe.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(input, medicationRe.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldFuzzDispRequest() {
        assertFalse(medicationRe.hasDispenseRequest());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasDispenseRequest());
        val input = new MedicationRequest.MedicationRequestDispenseRequestComponent().setQuantity(new SimpleQuantityImpl(fuzzerContext).generateRandom());
        medicationRe.setDispenseRequest(input.copy());
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(input.getQuantity(), medicationRe.getDispenseRequest().getQuantity());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(medicationRe.hasExtension());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasExtension());
        medicationRequestFuzz.fuzz(medicationRe);
        assertFalse(medicationRe.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        medicationRe.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(ext.getUrl(), medicationRe.getExtension().get(0).getUrl());
    }

    @Test()
    void shouldFuzzCompDate() {
        assertFalse(medicationRe.hasAuthoredOn());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasAuthoredOn());
        fuzzConfig.setPercentOfAll(100.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertFalse(medicationRe.hasAuthoredOn());
        val date = new Date(fuzzerContext.generateFakeLong());
        medicationRe.setAuthoredOn(new Date(date.getTime()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(date.getTime(), medicationRe.getAuthoredOn().getTime());
    }

    @Test()
    void shouldFuzzDosage() {
        assertFalse(medicationRe.hasDosageInstruction());
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasDosageInstruction());
        fuzzConfig.setPercentOfAll(100.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertFalse(medicationRe.hasDosageInstruction());
        val dosage = new DosageFuzzImpl(fuzzerContext).generateRandom();
        medicationRe.setDosageInstruction(List.of(dosage.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(dosage.getText(), medicationRe.getDosageInstruction().get(0).getText());
    }

    @Test
    void shouldAcceptDetailSetup() {
        fuzzerContext.getFuzzConfig().setDetailSetup(new HashMap<>());
        fuzzerContext.getFuzzConfig().getDetailSetup().put("KBV", "TRUE");
        assertFalse(medicationRe.hasIdentifier());
        medicationRequestFuzz.fuzz(medicationRe);
        assertFalse(medicationRe.hasIdentifier());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("KBV");
        medicationRequestFuzz.fuzz(medicationRe);
        assertTrue(medicationRe.hasIdentifier());
        fuzzConfig.setPercentOfAll(100.00f);
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        medicationRe.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        medicationRequestFuzz.fuzz(medicationRe);
        assertNotEquals(input, medicationRe.getIdentifier().get(0).getValue());
    }
}