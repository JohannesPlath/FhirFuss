/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes;

import de.gematik.test.fuzzing.fhirfuzz.BaseFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

@Slf4j
public class LanguageCodeFuzzerImpl implements BaseFuzzer<String> {
    private final FuzzerContext fuzzerContext;

    public LanguageCodeFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public String fuzz(String id) {
        if (id == null) {
            log.info("given String to fuzz was null!");
            return null;
        }
        char[] chars = id.toCharArray();
        for (int iter = 0; iter < chars.length; iter++) {
            if (fuzzerContext.conditionalChance(fuzzerContext.getFuzzConfig().getPercentOfEach() * 5)) {
                val cd = fuzzerContext.getFaker().regexify("[a-z]{1}");
                chars[iter] = cd.charAt(0);
            }
        }
        return String.valueOf(chars);
    }

    @Override
    public String generateRandom() {
        return fuzzerContext.getFaker().regexify("[a-z]{2}");
    }

}
