/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.StringFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AddressFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodeableConceptFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.HumanNameFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.NarrativeTypeFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Address;
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.Patient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PatientFuzzerImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static PatientFuzzerImpl patientFuzzer;
    private Patient patient;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        patientFuzzer = new PatientFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        patient = new Patient();
    }

    @Test
    void shouldFuzzId() {
        assertFalse(patient.hasId());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasId());
        patientFuzzer.fuzz(patient);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        patient.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(teststring, patient.getId());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(patient.hasMeta());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasMeta());
        patientFuzzer.fuzz(patient);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        patient.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(meta.getProfile(), patient.getMeta().getProfile());
    }

    @Test
    void shouldFuzzIdentifier() {
        assertFalse(patient.hasIdentifier());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasIdentifier());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        patient.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(input, patient.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldFuzzLang() {
        assertFalse(patient.hasLanguage());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasLanguage());
        fuzzConfig.setPercentOfAll(100.0f);
        patientFuzzer.fuzz(patient);
        val lang = new StringFuzzImpl(fuzzerContext).generateRandom(150);
        patient.setLanguage(lang);
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(lang, patient.getLanguage());
    }

    @Test
    void shouldFuzzActive() {
        assertFalse(patient.hasActive());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasActive());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.getActive());
        patient.setActive(true);
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertFalse(patient.getActive());
    }

    @Test
    void shouldFuzzText() {
        assertFalse(patient.hasText());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasText());
        patientFuzzer.fuzz(patient);
        val text = new NarrativeTypeFuzzer(fuzzerContext).generateRandom();
        patient.setText(text.copy());
        assertTrue(patient.hasText());
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(text.getId(), patient.getText().getId());
    }

    @Test
    void shouldFuzzName() {
        HumanName humanName = new HumanName();
        assertFalse(patient.hasName());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasName());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.hasName());
        val hName = new HumanNameFuzzerImpl(fuzzerContext).generateRandom();
        patient.setName(List.of(hName.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(hName.getFamily(), patient.getNameFirstRep().getFamily());
    }

    @Test
    void shouldFuzzAddress() {
        Address address = new AddressFuzzerImpl(fuzzerContext).generateRandom();
        assertFalse(patient.hasAddress());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasAddress());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.hasAddress());
        patient.setAddress(List.of(address.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(address.getCity(), patient.getAddress().get(0).getCity());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(patient.hasExtension());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasExtension());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        patient.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(ext.getUrl(), patient.getExtension().get(0).getUrl());
    }

    @Test
    void shouldFuzzMartialStatus() {
        val codableConc = new CodeableConceptFuzzer(fuzzerContext);
        assertFalse(patient.hasMaritalStatus());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasMaritalStatus());
        patientFuzzer.fuzz(patient);
        val m = codableConc.generateRandom();
        patient.setMaritalStatus(m.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(m, patient.getMaritalStatus());
    }

    @Test
    void shouldFuzzBithday() {
        assertFalse(patient.hasBirthDate());
        patientFuzzer.fuzz(patient);
        assertTrue(patient.hasBirthDate());
        patientFuzzer.fuzz(patient);
        assertFalse(patient.hasBirthDate());
        val bDay = fuzzerContext.getRandomDate();
        patient.setBirthDate(bDay);
        fuzzConfig.setPercentOfAll(0.00f);
        patientFuzzer.fuzz(patient);
        assertNotEquals(bDay.getTime(), patient.getBirthDate().getTime());
    }

}