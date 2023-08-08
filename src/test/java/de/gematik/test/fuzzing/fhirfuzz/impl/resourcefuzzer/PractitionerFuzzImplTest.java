/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AddressFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ContactPointFuzzImpl;
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
import org.hl7.fhir.r4.model.Practitioner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PractitionerFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static PractitionerFuzzImpl practitionerFuzz;

    private Practitioner practitioner;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        practitionerFuzz = new PractitionerFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        practitioner = new Practitioner();
    }

    @Test
    void shouldFuzzId() {
        assertFalse(practitioner.hasId());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasId());
        practitionerFuzz.fuzz(practitioner);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        practitioner.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(teststring, practitioner.getId());
        assertNotNull(practitioner.getId());
    }

    @Test
    void shouldFuzzLanguage() {
        assertFalse(practitioner.hasLanguage());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasLanguage());
        practitionerFuzz.fuzz(practitioner);
        val teststring = "123.345.5678";
        practitioner.setLanguage((teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(teststring, practitioner.getLanguage());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(practitioner.hasMeta());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasMeta());
        practitionerFuzz.fuzz(practitioner);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        practitioner.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(meta.getProfile(), practitioner.getMeta().getProfile());
    }

    @Test
    void shouldFuzzText() {
        assertFalse(practitioner.hasText());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasText());
        val testObject = new NarrativeTypeFuzzer(fuzzerContext).generateRandom();
        practitioner.setText(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(testObject, practitioner.getText());
    }

    @Test
    void shouldFuzzIdentifier() {
        assertFalse(practitioner.hasIdentifier());
        practitionerFuzz.fuzz(practitioner);
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        practitioner.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(input, practitioner.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldFuzzActive() {
        assertFalse(practitioner.hasActive());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasActive());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.getActive());
        practitioner.setActive(true);
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.getActive());
    }

    @Test
    void shouldFuzzName() {
        HumanName humanName = new HumanName();
        assertFalse(practitioner.hasName());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasName());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasName());
        val hName = new HumanNameFuzzerImpl(fuzzerContext).generateRandom();
        practitioner.setName(List.of(hName.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(hName.getFamily(), practitioner.getNameFirstRep().getFamily());
    }

    @Test
    void shouldFuzzAddress() {
        Address address = new AddressFuzzerImpl(fuzzerContext).generateRandom();
        assertFalse(practitioner.hasAddress());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasAddress());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasAddress());
        practitioner.setAddress(List.of(address.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(address.getCity(), practitioner.getAddress().get(0).getCity());
    }

    @Test
    void shouldFuzzBithday() {
        assertFalse(practitioner.hasBirthDate());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasBirthDate());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasBirthDate());
        val bDay = fuzzerContext.getRandomDate();
        practitioner.setBirthDate(bDay);
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(bDay.getTime(), practitioner.getBirthDate().getTime());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(practitioner.hasExtension());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasExtension());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        practitioner.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(ext.getUrl(), practitioner.getExtension().get(0).getUrl());
    }

    @Test
    void shouldFuzzTelcom() {
        assertFalse(practitioner.hasTelecom());
        practitionerFuzz.fuzz(practitioner);
        assertTrue(practitioner.hasTelecom());
        practitionerFuzz.fuzz(practitioner);
        assertFalse(practitioner.hasTelecom());
        val ext = new ContactPointFuzzImpl(fuzzerContext).generateRandom();
        practitioner.setTelecom(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        practitionerFuzz.fuzz(practitioner);
        assertNotEquals(ext.getValue(), practitioner.getTelecom().get(0).getValue());
    }

    @Test
    void shouldRespectDetailSetup() throws JsonProcessingException {
        Map details = new HashMap<>();
        details.put("KBV", "True");
        fuzzConfig.setDetailSetup(details);
        val pract = practitionerFuzz.generateRandom();
        //set Details out of space for KBV
        pract.setAddress(List.of(new AddressFuzzerImpl(fuzzerContext).generateRandom()));
        pract.setActive(true);
        val testAddress = pract.getAddress().get(0).getCity();
        val testIsActive = pract.getActive();
        practitionerFuzz.fuzz(pract);
        assertEquals(testAddress, pract.getAddress().get(0).getCity());
        assertEquals(testIsActive, pract.getActive());

        val om = new ObjectMapper();
        val jsonFile = om.writeValueAsString(fuzzConfig);
        System.out.println("\n\n joson: \n" + jsonFile);
        fuzzConfig.setDetailSetup(null);
        practitionerFuzz.fuzz(pract);
        assertTrue(pract.getAddress().isEmpty());
        assertNotEquals(testIsActive, pract.getActive());


    }
    @Test
    void generateRandom() {
        assertNotNull(practitionerFuzz.generateRandom().getAddress());
    }

    @Test
    void getContext() {
        assertNotNull(practitionerFuzz.getContext());
    }
}