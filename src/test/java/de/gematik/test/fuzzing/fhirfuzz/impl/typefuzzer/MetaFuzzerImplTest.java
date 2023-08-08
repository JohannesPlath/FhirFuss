/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.CanonicalType;
import org.hl7.fhir.r4.model.Coding;
import org.hl7.fhir.r4.model.Meta;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetaFuzzerImplTest {


    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static MetaFuzzerImpl metaFuzzer;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
    }


    @Test
    void shouldFuzzMetaVersion() {
        val meta = new Meta();
        var teststring = "12387973214ß0819230987231";
        meta.setVersionId(teststring);
        metaFuzzer.fuzz(meta);
        assertFalse(meta.getVersionId().isEmpty());
        assertNotEquals(teststring, meta.getVersionId());

    }

    @Test
    void shouldSetSource() {
        val meta = new Meta();
        var testString = "http://www.aroundTheWorld/aroundTheWorld/aroundThew/";
        meta.setSource(testString);
        metaFuzzer.fuzz(meta);
        val log = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));
        assertNotEquals(testString, meta.getSource());
        assertTrue(log.contains("Source"));
    }

    @Test
    void shouldFuzzProfileRef() {
        val meta = new Meta();
        var testString = "http://www.aroundTheWorld/aroundTheWorld/aroundThew/";
        var testString2 = "https://www.aroundTheJupiter/aroundTheJupiterWorld/aroundThew/";
        var testString3 = "http://www.aroundTheSun/aroundTheSun/aroundThe/";
        CanonicalType canonical = new CanonicalType(testString);
        CanonicalType canonical2 = new CanonicalType(testString2);
        CanonicalType canonical3 = new CanonicalType(testString3);
        List<CanonicalType> profiles = new ArrayList<>();
        profiles.add(canonical);
        profiles.add(canonical2);
        profiles.add(canonical3);
        meta.setProfile(profiles);
        metaFuzzer.fuzz(meta);
        val log = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));
        assertNotEquals(profiles.size(), meta.getProfile().size());

    }

    @Test
    void shouldFuzzMetaTags() {
        val meta = new Meta();
        var testString = "@NewBee";
        var testString2 = "@Doctor";
        var testString3 = "@Tester";
        Coding coding = new Coding("http//codingsys1", testString, "Very Useless but @ The Moment needful to test it");
        Coding coding2 = new Coding("http//codingsys2", testString2, "Very Useless but @ The Moment needful to test it");
        Coding coding3 = new Coding("http//codingsys3", testString3, "Very Useless but @ The Moment needful to test it");
        List<Coding> c = new ArrayList<>();
        c.add(coding);
        c.add(coding2);
        c.add(coding3);
        meta.setTag(c);
        metaFuzzer.fuzz(meta);
        val log = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));
        assertNotEquals(testString, meta.getTag().get(0).getCode());

    }
}