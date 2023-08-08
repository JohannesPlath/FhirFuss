/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes;

import de.gematik.test.fuzzing.fhirfuzz.BaseFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

@Slf4j
public class UrlFuzzImpl implements BaseFuzzer<String> {

    private final FuzzerContext fuzzerContext;

    public UrlFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public String fuzz(String s) {
        if (s == null) {
            log.info("given String at UriFuzzer was NULL");
            return this.generateRandom();
        }
        if (s.length() < 7)
            return s;
        val stringFuzz = new StringFuzzImpl(fuzzerContext);
        if (s.contains("https://")) {
            return "https://" + stringFuzz.fuzz(s.substring(8));
        }
        if (s.contains("Https://")) {
            return "Https://" + stringFuzz.fuzz(s.substring(8));
        }
        if (s.contains("http://")) {
            return "http://" + stringFuzz.fuzz(s.substring(7));
        }
        if (s.contains("Http://")) {
            return "Http://" + stringFuzz.fuzz(s.substring(7));
        }
        return stringFuzz.fuzz(s);
    }


    public String generateRandom() {
        return "https://" + fuzzerContext.getFaker().regexify("[a-z]{15}[/]{1}[a-z0-9?]{15}[/]{1}[a-z0-9?=]{20}");
    }
}
