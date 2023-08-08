/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.stringfuzz;

import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.IdFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.UrlFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Resource;


public class FhirBundleTemplateFuzzerDepricated extends Bundle {

    private final Bundle bundle;
    private final FuzzerContext fuzzerContext;


    public FhirBundleTemplateFuzzerDepricated(Bundle bundle, FuzzerContext fuzzerContext) {
        this.bundle = bundle;
        this.fuzzerContext = fuzzerContext;
    }

    public Bundle fuzzStrings() {
        var entries = bundle.getEntry();
        for (BundleEntryComponent x : entries) {
            if (fuzzerContext.conditionalChance()) {
                x.setResource(fuzzResourceId(x.getResource()));
            }
            if (fuzzerContext.conditionalChance()) {
                new UrlFuzzImpl(fuzzerContext).fuzz(x::getFullUrl, x::setFullUrl);
            }
        }
        bundle.setEntry(entries);
        return bundle;
    }

    private Resource fuzzResourceId(Resource resource) {
        if (fuzzerContext.conditionalChance()) {
            new IdFuzzerImpl(fuzzerContext).fuzz(resource::getId, resource::setId);

        }
        return resource;
    }


}
