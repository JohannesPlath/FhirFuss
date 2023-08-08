/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.erezept.fhir.exceptions.MissingFieldException;
import de.gematik.test.erezept.fhir.parser.EncodingType;
import de.gematik.test.erezept.fhir.parser.FhirParser;
import de.gematik.test.erezept.fhir.resources.kbv.KbvErpBundle;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.hl7.fhir.exceptions.FHIRFormatError;
import org.hl7.fhir.r4.model.Bundle;

import java.time.Instant;

import static java.text.MessageFormat.format;

@Slf4j
public class FuzzSafeRunner {

    private final FuzzConfig fuzzConfig;
    private final FuzzerContext fuzzerContext;
    private final FhirFuzzImpl fhirFuzz;
    private final FhirParser fhirParser;

    public FuzzSafeRunner(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
        this.fhirFuzz = new FhirFuzzImpl(fuzzerContext);
        fhirParser = new FhirParser();
        fuzzConfig = fuzzerContext.getFuzzConfig();
    }


    public Bundle generateFuzzedBundle(String stringXMLBundle) {
        Bundle bundle;
        try {
            bundle = getBundleFromXML(stringXMLBundle);
        } catch (MissingFieldException | FHIRFormatError | NullPointerException | IllegalArgumentException e) {
            log.info("given XML_String was no valid Bundle, Random Bundle will be used!!" + e);
            bundle = fhirFuzz.generateRandom();
        }
        return generateFuzzedBundle(bundle);
    }


    public Bundle generateFuzzedBundle(Bundle b) {
        Bundle bundle = fakeMissing(b);

        var xmlIsValidAfterFuzz = true;
        int counter = 1;
        for (int i = 0; i < (fuzzConfig.getIterations() > 0 ? fuzzConfig.getIterations() : 1); i++) {
            while (xmlIsValidAfterFuzz && counter <= 50) {
                fuzzerContext.addLog(new FuzzOperationResult<>(format("iteration no: {0} starts fuzzing at: ", (49 - i)), Instant.now(), fuzzConfig.toString()));
                try {
                    fhirFuzz.fuzz(bundle);
                    val xmlFuzzedBundle = fhirParser.encode(bundle, EncodingType.XML);
                    xmlIsValidAfterFuzz = fhirParser.isValid(xmlFuzzedBundle);
                } catch (MissingFieldException | FHIRFormatError e) {
                    log.info(String.valueOf(e));
                }
                counter++;
            }
        }
        return bundle;
    }

    private Bundle getBundleFromXML(String stringXMLBundle) throws MissingFieldException, FHIRFormatError, NullPointerException, IllegalArgumentException {
        Bundle bundle;
        if (stringXMLBundle == null
                || stringXMLBundle.length() < 5
                || !fhirParser.isValid(stringXMLBundle)) {
            throw new IllegalArgumentException("given XML String is no valid Bundle");
        } else {
            bundle = fhirParser.decode(KbvErpBundle.class, stringXMLBundle);
        }
        return bundle;
    }

    private Bundle fakeMissing(Bundle bundle) {
        if (bundle == null || bundle.isEmpty() || fhirParser.isValid(bundle)) {
            log.info("given Bundle was no valid bundle, random Bundle will be used");
            return fhirFuzz.generateRandom();
        } else {
            return bundle;
        }
    }

}
