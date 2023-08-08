/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.StringType;
import org.hl7.fhir.r4.model.UriType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExtensionFuzzerImplTest {


    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static ExtensionFuzzerImpl extensionFuzzerImpl;

    private Extension extension;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        extensionFuzzerImpl = new ExtensionFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        extension = new Extension();
    }

    @Test
    void getContext() {
        assertNotNull(extensionFuzzerImpl.getContext());
    }

    @Test
    void generateRandom() {
        assertTrue(extensionFuzzerImpl.generateRandom().hasUrl());
        assertTrue(extensionFuzzerImpl.generateRandom().hasUrlElement());
    }

    @Test
    void shouldFuzzUrl() {
        assertFalse(extension.hasUrl());
        extensionFuzzerImpl.fuzz(extension);
        assertTrue(extension.hasUrl());
        extensionFuzzerImpl.fuzz(extension);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        extension.setUrl(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        extensionFuzzerImpl.fuzz(extension);
        assertNotEquals(teststring, extension.getId());
    }

    @Test
    void shouldFuzzId() {
        assertFalse(extension.hasId());
        extensionFuzzerImpl.fuzz(extension);
        assertTrue(extension.hasId());
        extensionFuzzerImpl.fuzz(extension);
        val teststring = fuzzerContext.getIdFuzzer().generateRandom();
        extension.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        extensionFuzzerImpl.fuzz(extension);
        assertNotEquals(teststring, extension.getId());
    }

    @Test
    void shouldFuzzUrlElement() {
        assertFalse(extension.hasUrlElement());
        extensionFuzzerImpl.fuzz(extension);
        assertTrue(extension.hasUrlElement());
        extensionFuzzerImpl.fuzz(extension);
        val teststring = new UriType(fuzzerContext.getStringFuzz().generateRandom(150));
        extension.setUrlElement(teststring.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        extensionFuzzerImpl.fuzz(extension);
        assertNotEquals(teststring.toString(), extension.getUrlElement().toString());
    }

    @Test
    void shouldFuzzIdElement() {
        assertFalse(extension.hasIdElement());
        extensionFuzzerImpl.fuzz(extension);
        assertTrue(extension.hasIdElement());
        extensionFuzzerImpl.fuzz(extension);
        val teststring = fuzzerContext.getIdFuzzer().generateRandom();
        extension.setIdElement(new StringType(teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        extensionFuzzerImpl.fuzz(extension);
        assertNotEquals(teststring, extension.getIdElement().toString());
    }

    @Test
    void shouldAcceptDetailSetup() {
        assertFalse(extension.hasIdElement());
        extensionFuzzerImpl.fuzz(extension);
        assertTrue(extension.hasIdElement());
        val testObject = extension.getValue();
        fuzzerContext.getFuzzConfig().setDetailSetup(new HashMap<>());
        fuzzerContext.getFuzzConfig().getDetailSetup().put("TriggertByMedRequest", "TRUE");
        fuzzerContext.getFuzzConfig().getDetailSetup().put("KBV", "TRUE");
        extensionFuzzerImpl.fuzz(extension);
        assertEquals(testObject, extension.getValue());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("TriggertByMedRequest");
        extensionFuzzerImpl.fuzz(extension);
        assertNotEquals(testObject, extension.getValue());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("KBV");
    }


}