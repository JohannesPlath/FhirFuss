/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodeableConceptFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodingTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CodeableConceptFuzzerTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static CodeableConceptFuzzer codeableConceptFuzzer;

    private CodeableConcept cc;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        codeableConceptFuzzer = new CodeableConceptFuzzer(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        cc = new CodeableConcept();
    }

    @Test
    void getContext() {
        assertNotNull(codeableConceptFuzzer.getContext());
    }

    @Test
    void generateRandom() {
        assertTrue(codeableConceptFuzzer.generateRandom().hasText());
        assertTrue(codeableConceptFuzzer.generateRandom().hasCoding());

    }

    @Test
    void shouldFuzzText() {
        assertFalse(cc.hasText());
        codeableConceptFuzzer.fuzz(cc);
        assertTrue(cc.hasText());
        codeableConceptFuzzer.fuzz(cc);
        val teststring = fuzzerContext.getStringFuzz().generateRandom(150);
        cc.setText(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        codeableConceptFuzzer.fuzz(cc);
        assertNotEquals(teststring, cc.getText());
    }

    @Test
    void shouldFuzzId() {
        assertFalse(cc.hasId());
        codeableConceptFuzzer.fuzz(cc);
        assertTrue(cc.hasId());
        codeableConceptFuzzer.fuzz(cc);
        val teststring = fuzzerContext.getIdFuzzer().generateRandom();
        cc.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        codeableConceptFuzzer.fuzz(cc);
        assertNotEquals(teststring, cc.getId());
    }

    @Test
    void shouldFuzzCoding() {
        assertFalse(cc.hasCoding());
        codeableConceptFuzzer.fuzz(cc);
        assertTrue(cc.hasCoding());
        codeableConceptFuzzer.fuzz(cc);
        assertFalse(cc.hasCoding());
        val codings = new CodingTypeFuzzerImpl(fuzzerContext).generateRandomCodingList();
        val teststring = codings.get(0).getId();
        cc.setCoding(codings);
        fuzzConfig.setPercentOfAll(0.00f);
        codeableConceptFuzzer.fuzz(cc);
        assertNotEquals(teststring, cc.getCoding().get(0).getId());
    }

    @Test
    void shouldFuzzExtension() {
        assertFalse(cc.hasExtension());
        codeableConceptFuzzer.fuzz(cc);
        assertTrue(cc.hasExtension());
        codeableConceptFuzzer.fuzz(cc);
        assertFalse(cc.hasExtension());

    }
}