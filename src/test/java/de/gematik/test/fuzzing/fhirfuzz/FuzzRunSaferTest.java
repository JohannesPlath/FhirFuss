/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.erezept.fhir.builder.kbv.KbvErpBundleBuilder;
import de.gematik.test.erezept.fhir.parser.FhirParser;
import de.gematik.test.erezept.fhir.util.ResourceUtils;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;

@Slf4j
class FuzzRunSaferTest {
    static FhirParser fhirParser;
    static FuzzSafeRunner fuzzRunSaver;

    @BeforeAll
    static void setup() {
        fhirParser = new FhirParser();
        FuzzerContext fuzzerContext = new FuzzerContext(FuzzConfig.getRandom());
        fuzzerContext.getFuzzConfig().setUseAllMutators(true);
        fuzzerContext.getFuzzConfig().setPercentOfEach(80.0f);
        fuzzerContext.getFuzzConfig().setPercentOfAll(80.0f);
        Map details = new HashMap<>();
        details.put("KBV", "True");
        fuzzerContext.getFuzzConfig().setDetailSetup(details);
        fuzzRunSaver = new FuzzSafeRunner(fuzzerContext);
    }

    @RepeatedTest(1)
    void fuzzWithXmlString() {
        val pathToBundle2 = "fhir/valid/kbv/1.1.0/bundle/5a3458b0-8364-4682-96e2-b262b2ab16eb.xml";
        String stringBundle = "";
        try {
            stringBundle = readFromFile(pathToBundle2);
        } catch (Exception e) {
            log.info(" can´t read file " + e);
        }
        val newBundle = fuzzRunSaver.generateFuzzedBundle(stringBundle);
        assertFalse(fhirParser.isValid(newBundle));
    }

    @RepeatedTest(1)
    void fuzzWithRandomBundle() {
        val newBundle = fuzzRunSaver.generateFuzzedBundle(KbvErpBundleBuilder.faker().build());

        assertFalse(fhirParser.isValid(newBundle));
    }

    private String readFromFile(String file) {
        return ResourceUtils.readFileFromResource(file);
    }

}