/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodingTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Period;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentifierFuzzerImplTest {

    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static final String TESTSTRING = "TestSTRING";
    private static IdentifierFuzzerImpl fhirIdentifierFuzzer;
    private Identifier identifier;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        fhirIdentifierFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupIdentifier() {
        identifier = new Identifier();

    }

    @Test
    void shouldGenerateRandom() {
        val result = fhirIdentifierFuzzer.generateRandom();
        assertNotNull(fhirIdentifierFuzzer.generateRandom());
        assertNotNull(result.getSystem());
        assertNotNull(result.getUse());
        assertNotNull(result.getValue());
        assertNotNull(result.getType());
        assertNotNull(result.getPeriod());
    }




    @Test
    void shouldFuzzValue() {
        identifier = fhirIdentifierFuzzer.generateRandom();
        val testObject = identifier.getValue();
        fhirIdentifierFuzzer.fuzz(identifier);
        assertNotEquals(testObject, identifier.getValue());
    }

    @Test
    void shouldFuzzAndValidate() {
        val testobject = "123123123123345654676798890ßü+ß´0";
        identifier.setSystem(testobject);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertNotEquals(testobject, identifier.getSystem());
    }

    @Test
    void shouldFuzzIdentifierType() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        var codingTypeFuzzer = new CodingTypeFuzzerImpl(fuzzerContext);
        assertFalse(identifier.hasType());
        val input = codingTypeFuzzer.gerateRandomCodingConcept();
        identifier.setType(input.copy());
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasType());
        fuzzConfig.setPercentOfAll(100.0f);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertNotEquals(input, identifier.getType());
    }

    @Test
    void shouldFuzzIdentifierUse() {

        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        val use = fuzzerContext.getRandomOneOfClass(Identifier.IdentifierUse.class, Identifier.IdentifierUse.NULL);
        assertFalse(identifier.hasUse());
        identifier.setUse(use);
        assertTrue(identifier.hasUse());
        fuzzConfig.setPercentOfAll(100.0f);
        fhirIdentifierFuzzer.fuzz(identifier);

        fuzzConfig.setPercentOfAll(00.0f);
        identifier.setUse(use);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasUse());
        assertNotEquals(use, identifier.getUse());

    }

    @Test
    void shouldFuzzIdentifierSystem() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        val system = TESTSTRING;
        assertFalse(identifier.hasSystem());
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasSystem());
        fuzzConfig.setPercentOfAll(100.0f);
        fhirIdentifierFuzzer.fuzz(identifier);
        fuzzConfig.setPercentOfAll(00.0f);
        identifier.setSystem(system);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasUse());
        assertNotEquals(system, identifier.getSystem());

    }

    @Test
    void shouldFuzzIdentifierValue() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        val system = TESTSTRING;
        assertFalse(identifier.hasSystem());
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasSystem());
        fuzzConfig.setPercentOfAll(100.0f);
        fhirIdentifierFuzzer.fuzz(identifier);
        identifier.setSystem(system);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasUse());
        assertNotEquals(system, identifier.getSystem());

    }

    @Test
    void shouldFuzzIdentifierPeriod() {
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setPercentOfAll(00.0f);
        val period = new Period();
        assertFalse(identifier.hasPeriod());
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasPeriod());
        fuzzConfig.setPercentOfAll(100.0f);
        fhirIdentifierFuzzer.fuzz(identifier);
        identifier.setPeriod(period);
        fhirIdentifierFuzzer.fuzz(identifier);
        assertTrue(identifier.hasPeriod());
        assertNotEquals(period, identifier.getPeriod());

    }


}