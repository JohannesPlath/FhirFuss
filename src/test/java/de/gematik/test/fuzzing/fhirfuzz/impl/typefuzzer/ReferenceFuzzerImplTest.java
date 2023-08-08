/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ReferenceFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Reference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReferenceFuzzerImplTest {
    static ReferenceFuzzerImpl referenceFuzzer;

    static FuzzerContext fuzzerContext;

    Reference reference;

    @BeforeAll
    static void setup() {
        val fuzzConf = new FuzzConfig();
        fuzzConf.setUseAllMutators(true);
        fuzzConf.setPercentOfEach(100f);
        fuzzConf.setDetailSetup(new HashMap<>());
        fuzzerContext = new FuzzerContext(fuzzConf);
        referenceFuzzer = new ReferenceFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupReference() {
        reference = new Reference();
    }

    @Test
    void shouldRenerateRandomRef() {
        val ref = referenceFuzzer.generateRandom();
        assertNotNull(ref.getReference());
        assertNotNull(ref.getType());
        assertNotNull(ref.getIdentifier());
        assertNotNull(ref.getDisplay());

    }


    @Test
    void shouldFuzzReference() {
        reference.setReference(null);
        assertNull(reference.getReference());
        referenceFuzzer.fuzz(reference);
        assertNotNull(reference.getReference());
        fuzzerContext.getFuzzConfig().setPercentOfAll(100.00f);
        referenceFuzzer.fuzz(reference);
        fuzzerContext.getFuzzConfig().setPercentOfAll(00.00f);
        val s = fuzzerContext.getStringFuzz().generateRandom(200);
        reference.setReference(s);
        referenceFuzzer.fuzz(reference);
        assertNotEquals(s, reference.getReference());
    }

    @Test
    void shouldFuzzType() {
        reference.setType(null);
        assertNull(reference.getType());
        referenceFuzzer.fuzz(reference);
        assertTrue(reference.hasType());
        fuzzerContext.getFuzzConfig().setPercentOfAll(100.00f);
        referenceFuzzer.fuzz(reference);
        fuzzerContext.getFuzzConfig().setPercentOfAll(00.00f);
        val s = fuzzerContext.getStringFuzz().generateRandom(100);
        reference.setType(s);
        referenceFuzzer.fuzz(reference);
        assertNotEquals(s, reference.getType());
    }

    @Test
    void shouldFuzzIdentifier() {
        reference.setIdentifier(null);
        assertFalse(reference.hasIdentifier());
        referenceFuzzer.fuzz(reference);
        assertTrue(reference.hasIdentifier());
        fuzzerContext.getFuzzConfig().setPercentOfAll(100.00f);
        referenceFuzzer.fuzz(reference);
        fuzzerContext.getFuzzConfig().setPercentOfAll(00.00f);
        val ident = new IdentifierFuzzerImpl(fuzzerContext).generateRandom();
        reference.setIdentifier(ident.copy());
        referenceFuzzer.fuzz(reference);
        assertNotEquals(ident.getValue(), reference.getIdentifier().getValue());
    }

    @Test
    void shouldFuzzDisplay() {
        reference.setDisplay(null);
        assertFalse(reference.hasDisplay());
        referenceFuzzer.fuzz(reference);
        assertTrue(reference.hasDisplay());
        fuzzerContext.getFuzzConfig().setPercentOfAll(100.00f);
        referenceFuzzer.fuzz(reference);
        fuzzerContext.getFuzzConfig().setPercentOfAll(00.00f);
        val s = fuzzerContext.getStringFuzz().generateRandom(150);
        reference.setDisplay(s);
        referenceFuzzer.fuzz(reference);
        assertNotEquals(s, reference.getDisplay());
    }

    @Test
    void shouldAcceptDetailSetupAndFuzzesCodeText() {
        assertFalse(reference.hasDisplay());
        referenceFuzzer.fuzz(reference);
        assertTrue(reference.hasDisplay());
        reference.setDisplay("123");
        assertFalse(reference.getDisplay().length() > 50);
        fuzzerContext.getFuzzConfig().getDetailSetup().put("BreakRanges", "TRUE");
        referenceFuzzer.fuzz(reference);
        assertTrue(reference.getDisplay().length() > 50);
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("BreakRanges");
    }

}