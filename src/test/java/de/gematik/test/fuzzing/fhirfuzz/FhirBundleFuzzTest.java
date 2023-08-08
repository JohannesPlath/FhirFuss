/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.erezept.fhir.builder.kbv.KbvErpBundleBuilder;
import de.gematik.test.erezept.fhir.parser.EncodingType;
import de.gematik.test.erezept.fhir.parser.FhirParser;
import de.gematik.test.erezept.fhir.resources.kbv.KbvErpBundle;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.stream.Collectors;

import static java.text.MessageFormat.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
class FhirBundleFuzzTest {

    static FhirParser fhirParser;


    //toDo reduce
    static final String DOCUMENT_PATH = "src/main/java/de/gematik/test/fuzzing/fhirfuzz/documents/";

    @BeforeAll

    static void setup() {
        fhirParser = new FhirParser();
    }

    @Test
    void shouldNotFuzzBundleWithoutConf() {

        val orgBundle = KbvErpBundleBuilder.faker().build();//.builder().build();
        val bundleCopy = new KbvErpBundle();
        orgBundle.copyValues(bundleCopy);
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(0.0f);
        fuzzConfig.setPercentOfAll(0.0f);
        fuzzConfig.setUsedPercentOfMutators(0.0f);
        fuzzConfig.setUseAllMutators(false);
        FuzzerContext fuzzerContext = new FuzzerContext(fuzzConfig);
        FhirFuzzImpl fhirBundleFuzz = new FhirFuzzImpl(fuzzerContext);
        fhirBundleFuzz.fuzz(orgBundle);
        assertEquals(bundleCopy.getIdentifier().getValue(), orgBundle.getIdentifier().getValue());

        val fuzzLog = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));
        System.out.println("\n in \nshouldNotFuzzBundleWithoutConf, fuzzlog: \n" + fuzzLog);
        val jsonFuzzedBundle = fhirParser.encode(orgBundle, EncodingType.JSON);
        val isValidBundle = fhirParser.isValid(jsonFuzzedBundle);
        val result = fhirParser.validate(jsonFuzzedBundle);
        result.getMessages().forEach(m -> System.out.println(m));
        assertTrue(isValidBundle);
    }

    @SneakyThrows
    @Test
    void shouldFuzzBundleWithConf() {
        //System.setProperty("erp.fhir.profile", "ERP_FHIR_PROFILE=1.2.0");
        val orgBundle = KbvErpBundleBuilder.faker().build();
        val jsonFuzzedBundle = fhirParser.encode(orgBundle, EncodingType.JSON);
        val isValidBundle = fhirParser.isValid(jsonFuzzedBundle);
        val isValidBeforeFuzz = "_isValid_" + isValidBundle;


        val bundleCopy = new KbvErpBundle();
        orgBundle.copyValues(bundleCopy);
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(0.0f);
        fuzzConfig.setPercentOfAll(20.0f);
        fuzzConfig.setUsedPercentOfMutators(50.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzConfig.setShouldPrintToFile(false);
        FuzzerContext fuzzerContext = new FuzzerContext(fuzzConfig);
        FhirFuzzImpl fhirBundleResourceFuzz = new FhirFuzzImpl(fuzzerContext);
        fhirBundleResourceFuzz.fuzz(orgBundle);
        val fuzzLog = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));

        try {
            fuzzerContext.addLog(new FuzzOperationResult<>("start fuzzing at: ", Instant.now(), fuzzConfig.toString()));
            val jsonFuzzedBundle2 = fhirParser.encode(orgBundle, EncodingType.JSON);
            val jsonOriginalBundle = fhirParser.encode(bundleCopy, EncodingType.JSON);
            boolean isValidBundle2 = false;


            String isValidAfterFuzz = "_isValid_" + isValidBundle2;
            val result = fhirParser.validate(jsonFuzzedBundle);

            result.getMessages().forEach(m -> System.out.println(m));

            if (fuzzConfig.getShouldPrintToFile()) {
                writeStringUsingBufferedWriter(jsonFuzzedBundle2, format("{0}fuzzedBundle{1}.json", DOCUMENT_PATH, isValidAfterFuzz));
                writeStringUsingBufferedWriter(fuzzLog, format("{0}fuzzLog{1}.txt", DOCUMENT_PATH, isValidAfterFuzz));
                writeStringUsingBufferedWriter(jsonOriginalBundle, format("{0}orgBundle{1}.json", DOCUMENT_PATH, isValidBeforeFuzz));
            }
        } catch (ca.uhn.fhir.parser.DataFormatException | IOException e) {
            log.info(e.toString());
        }
    }

    @Test
    void shouldFuzzWithStringCompare() {
        val orgBundle = KbvErpBundleBuilder.faker().build();
        val bundleCopy = new KbvErpBundle();
        orgBundle.copyValues(bundleCopy);
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(3.0f);
        fuzzConfig.setPercentOfAll(3.0f);
        fuzzConfig.setUseAllMutators(false);
        FuzzerContext fuzzerContext = new FuzzerContext(fuzzConfig);
        FhirFuzzImpl fhirBundleResourceFuzz = new FhirFuzzImpl(fuzzerContext);

        try {
            fuzzerContext.addLog(new FuzzOperationResult<>("start fuzzing at: ", Instant.now(), fuzzConfig.toString()));

            val jsonUnfuzzedBundle = fhirParser.encode(orgBundle, EncodingType.JSON);
            fhirBundleResourceFuzz.fuzz(orgBundle);

            val fuzzLog = fuzzerContext.getOperationLogs().stream().map(Object::toString).collect(Collectors.joining("\n"));
            val jsonFuzzedBundle = fhirParser.encode(orgBundle, EncodingType.JSON);
            val jsonCopyBundle = fhirParser.encode(bundleCopy, EncodingType.JSON);
            val compUnfuzzAndFuzzed = jsonUnfuzzedBundle.compareTo(jsonFuzzedBundle);
            val compCopyAndUnfuzz = jsonCopyBundle.compareTo(jsonUnfuzzedBundle);
            val compCopyAndFuzzed = jsonFuzzedBundle.compareTo(jsonCopyBundle);
            log.info("shouldFuzzWithStringCompare() \n" + fuzzLog);

            val isValidBundle = fhirParser.isValid(jsonFuzzedBundle);
            val result = fhirParser.validate(jsonFuzzedBundle);

            result.getMessages().forEach(m -> System.out.println(m));
//            assertEquals(0, compCopyAndUnfuzz);
//            assertNotEquals(0, compCopyAndFuzzed);
//            assertNotEquals(0, compUnfuzzAndFuzzed);
        } catch (Exception e) {
            log.info(String.valueOf(e));
        }

    }
    @SuppressWarnings("java:S6300")
    public void writeStringUsingBufferedWriter(String bundle, String file) throws IOException {
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new FileWriter(file));
            writer.write(bundle);
            writer.close();
        } catch (IOException e) {
            log.info("BufferedWriter throw IOException ", e);
        } finally {
            if (writer != null)
                writer.close();
        }
    }

}