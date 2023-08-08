/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodingTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ReferenceFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Composition;
import org.hl7.fhir.r4.model.Identifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompositionFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static CompositionFuzzImpl compFuzzer;
    private Composition composition;
    private static final String TESTSTRING = "TestSTRING";

    private final int TESTITERATIONS = 1;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setDetailSetup(new HashMap<>());
        fuzzerContext = new FuzzerContext(fuzzConfig);
        compFuzzer = new CompositionFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        composition = new Composition();
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldGetRandomCompStatus() {
        assertNotNull(fuzzerContext.getRandomOneOfClass(Composition.CompositionStatus.class));
    }

    @Test
    void getRandomEnum() {
        val e = fuzzerContext.getRandomOneOfClass(Composition.CompositionStatus.class);
        assertNotNull(e);
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzId() {
        assertFalse(composition.hasId());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasId());
        compFuzzer.fuzz(composition);
        val teststring = fuzzerContext.getIdFuzzer().generateRandom();
        composition.setId(teststring);
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(teststring, composition.getId());
    }

    @RepeatedTest(TESTITERATIONS)
    void shoulFuzzIdentifier() {
        assertFalse(composition.hasIdentifier());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasIdentifier());
        compFuzzer.fuzz(composition);
        Identifier identifier = new Identifier();
        val teststring = "123.345.5678";
        composition.setIdentifier(identifier.setSystem(teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(teststring, composition.getIdentifier().getSystem());
    }

    @RepeatedTest(TESTITERATIONS)
    void shoulFuzzLanguage() {
        assertFalse(composition.hasLanguage());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasLanguage());
        compFuzzer.fuzz(composition);
        val teststring = "123.345.5678";
        composition.setLanguage((teststring));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(teststring, composition.getLanguage());
    }


    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompStatus() {
        assertFalse(composition.hasStatus());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasStatus());
        assertNotNull(composition.getStatus());
        val status = fuzzerContext.getRandomOneOfClass(Composition.CompositionStatus.class);
        composition.setStatus(status);
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(status, composition.getStatus());

    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompMeta() {
        assertFalse(composition.hasMeta());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasMeta());
        assertNotNull(composition.getMeta());
        compFuzzer.fuzz(composition);
        MetaFuzzerImpl metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
        val meta = metaFuzzer.generateRandom();
        composition.setMeta(meta.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(meta.getProfile(), composition.getMeta().getProfile());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompType() {
        assertFalse(composition.hasType());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasType());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        CodingTypeFuzzerImpl codingTypeFuzzerImpl = new CodingTypeFuzzerImpl(fuzzerContext);
        val type = codingTypeFuzzerImpl.gerateRandomCodingConcept();
        composition.setType(type.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(type.getCodingFirstRep(), composition.getType().getCodingFirstRep());
    }


    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompSubject() {
        assertFalse(composition.hasSubject());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasSubject());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        ReferenceFuzzerImpl referenceFuzzer = new ReferenceFuzzerImpl(fuzzerContext);
        val ref = referenceFuzzer.generateRandom();
        composition.setSubject(ref.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref.getReference(), composition.getSubject().getReference());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompEncounter() {
        assertFalse(composition.hasEncounter());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasEncounter());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        ReferenceFuzzerImpl referenceFuzzer = new ReferenceFuzzerImpl(fuzzerContext);
        val ref = referenceFuzzer.generateRandom();
        composition.setEncounter(ref.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref.getReference(), composition.getEncounter().getReference());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompDate() {
        assertFalse(composition.hasDate());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasDate());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        assertFalse(composition.hasDate());
        val date = new Date(fuzzerContext.generateFakeLong());
        composition.setDate(new Date(date.getTime()));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(date.getTime(), composition.getDate().getTime());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompAuthor() {
        assertFalse(composition.hasAuthor());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasAuthor());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        assertFalse(composition.hasAuthor());
        ReferenceFuzzerImpl referenceFuzzer = new ReferenceFuzzerImpl(fuzzerContext);
        val ref = referenceFuzzer.generateRandom();
        composition.setAuthor(List.of(ref.copy()));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref.getReference(), composition.getAuthor().get(0).getReference());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompTitle() {
        assertFalse(composition.hasTitle());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasTitle());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        val ref = TESTSTRING;
        composition.setTitle(ref);
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref, composition.getTitle());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompConfidentiality() {
        assertFalse(composition.hasConfidentiality());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasConfidentiality());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        val ref = TESTSTRING;
        composition.setConfidentiality(fuzzerContext.getRandomOneOfClass(Composition.DocumentConfidentiality.class));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref, composition.getConfidentiality());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompCustodian() {
        assertFalse(composition.hasCustodian());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasCustodian());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        ReferenceFuzzerImpl referenceFuzzer = new ReferenceFuzzerImpl(fuzzerContext);
        val ref = referenceFuzzer.generateRandom();
        composition.setCustodian(ref.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref, composition.getCustodian());
    }

    @RepeatedTest(TESTITERATIONS)
    void shouldFuzzCompRelatesTo() {
        assertFalse(composition.hasRelatesTo());
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasRelatesTo());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        val ref = new Composition.CompositionRelatesToComponent();
        composition.setRelatesTo(List.of(ref));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref, composition.getRelatesToFirstRep());
    }

    @Test
    void shouldAcceptDetailSetup() {
        fuzzerContext.getFuzzConfig().setDetailSetup(new HashMap<>());
        fuzzerContext.getFuzzConfig().getDetailSetup().put("KBV", "TRUE");
        assertFalse(composition.hasConfidentiality());
        compFuzzer.fuzz(composition);
        assertFalse(composition.hasConfidentiality());
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("KBV");
        compFuzzer.fuzz(composition);
        assertTrue(composition.hasConfidentiality());
        fuzzConfig.setPercentOfAll(100.00f);
        compFuzzer.fuzz(composition);
        val ref = TESTSTRING;
        composition.setConfidentiality(fuzzerContext.getRandomOneOfClass(Composition.DocumentConfidentiality.class));
        fuzzConfig.setPercentOfAll(0.00f);
        compFuzzer.fuzz(composition);
        assertNotEquals(ref, composition.getConfidentiality());
    }

    @Test
    void shouldGenerateRandom() {
        assertNotNull(compFuzzer.generateRandom());
    }

    @Test
    void shouldgetContext() {
        assertNotNull(compFuzzer.getContext());
    }

}










