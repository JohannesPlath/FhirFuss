/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AddressFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ContactPointFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.NarrativeTypeFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Address;
import org.hl7.fhir.r4.model.Organization;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OrganisationFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static OrganisationFuzzImpl organisationFuzz;
    private Organization organization;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        organisationFuzz = new OrganisationFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        organization = new Organization();
    }

    @Test
    void shouldFuzzId() {
        assertFalse(organization.hasId());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasId());
        organisationFuzz.fuzz(organization);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        organization.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(teststring, organization.getId());
    }

    @Test
    void shouldFuzzLanguage() {
        assertFalse(organization.hasLanguage());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasLanguage());
        organisationFuzz.fuzz(organization);
        val teststring = "123.345.5678";
        organization.setLanguage((teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(teststring, organization.getLanguage());
    }

    @Test
    void shouldFuzzMeta() {
        assertFalse(organization.hasMeta());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasMeta());
        organisationFuzz.fuzz(organization);
        val meta = new MetaFuzzerImpl(fuzzerContext).generateRandom();
        organization.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(meta.getProfile(), organization.getMeta().getProfile());
    }

    @Test
    void shouldFuzzText() {
        assertFalse(organization.hasText());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasText());
        val testObject = new NarrativeTypeFuzzer(fuzzerContext).generateRandom();
        organization.setText(testObject.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(testObject, organization.getText());
    }

    @Test
    void shouldFuzzIdentifier() {
        assertFalse(organization.hasIdentifier());
        organisationFuzz.fuzz(organization);
        organisationFuzz.fuzz(organization);
        assertFalse(organization.hasIdentifier());
        val identiList = List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom());
        val input = identiList.get(0).getValue();
        organization.setIdentifier(identiList);
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(input, organization.getIdentifier().get(0).getValue());
    }

    @Test
    void shouldFuzzActive() {
        assertFalse(organization.hasActive());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasActive());
        organisationFuzz.fuzz(organization);
        assertFalse(organization.getActive());
        organization.setActive(true);
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertFalse(organization.getActive());
    }

    @Test
    void shouldFuzzName() {
        assertFalse(organization.hasName());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasName());
        val hName = fuzzerContext.getStringFuzz().generateRandom(15);
        organization.setName(hName);
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(hName, organization.getName());
    }

    @Test
    void shouldFuzzAddress() {
        Address address = new AddressFuzzerImpl(fuzzerContext).generateRandom();
        assertFalse(organization.hasAddress());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasAddress());
        organisationFuzz.fuzz(organization);
        assertFalse(organization.hasAddress());
        organization.setAddress(List.of(address.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(address.getCity(), organization.getAddress().get(0).getCity());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(organization.hasExtension());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasExtension());
        organisationFuzz.fuzz(organization);
        assertFalse(organization.hasExtension());
        val ext = new ExtensionFuzzerImpl(fuzzerContext).generateRandom();
        organization.setExtension(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(ext.getUrl(), organization.getExtension().get(0).getUrl());
    }

    @Test
    void shouldFuzzTelcom() {
        assertFalse(organization.hasTelecom());
        organisationFuzz.fuzz(organization);
        assertTrue(organization.hasTelecom());
        organisationFuzz.fuzz(organization);
        assertFalse(organization.hasTelecom());
        val ext = new ContactPointFuzzImpl(fuzzerContext).generateRandom();
        organization.setTelecom(List.of(ext.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        organisationFuzz.fuzz(organization);
        assertNotEquals(ext.getValue(), organization.getTelecom().get(0).getValue());
    }

    @Test
    void generateRandom() {
        assertNotNull(organisationFuzz.generateRandom().getAddress());
    }

    @Test
    void getContext() {
        assertNotNull(organisationFuzz.getContext());
    }
}