/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;


import de.gematik.test.erezept.fhir.builder.kbv.KbvErpBundleBuilder;
import de.gematik.test.fuzzing.fhirfuzz.stringfuzz.FhirBundleTemplateFuzzerDepricated;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.junit.Ignore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class FhirBundleTemplateFuzzerDepricatedTest {


    @Ignore
        // todo check in august
    void resourceIdShouldNotEqual() {
        val orgBundle = KbvErpBundleBuilder.builder().build();
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        FuzzerContext fuzzerContext = new FuzzerContext(fuzzConfig);
        var stringFuzzer = new FhirBundleTemplateFuzzerDepricated(orgBundle, fuzzerContext);
        var orgResId = orgBundle.getEntry().get(0).getResource().getId();
        val newBundle = stringFuzzer.fuzzStrings();
        assertEquals(orgBundle, newBundle);
        assertNotEquals(orgResId, newBundle.getEntry().get(0).getResource().getId());
    }

    @Ignore
        // todo check in august
    void entryUrlShouldNotEqual() {
        val orgBundle = KbvErpBundleBuilder.faker().build();
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(50.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        FuzzerContext fuzzerContext = new FuzzerContext(fuzzConfig);
        var stringFuzzer = new FhirBundleTemplateFuzzerDepricated(orgBundle, fuzzerContext);
        var orgBundleUrl = orgBundle.getEntry().get(0).getFullUrl();
        val newBundle = stringFuzzer.fuzzStrings();
        assertEquals(orgBundle, newBundle);
        assertNotEquals(orgBundleUrl, newBundle.getEntry().get(0).getFullUrl());
    }

}