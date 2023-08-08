/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlFuzzImplTest {
    static FuzzConfig fuzzConfig;
    static FuzzerContext fuzzerContext;
    static UrlFuzzImpl uriFuzzer;

    @BeforeAll
    static void setup() {
        fuzzConfig = new FuzzConfig();
        fuzzerContext = new FuzzerContext(fuzzConfig);
        uriFuzzer = new UrlFuzzImpl(fuzzerContext);
    }

    @Test
    void getContext() {
        assertNotNull(uriFuzzer.getContext());
    }

    @ParameterizedTest
    @CsvSource({
            "'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 40 ",
            "'Http://www.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccccccccccc,mlknweoiflnkyxlknasdpo90ß32msc.,mpo0.,ascd', 15",
            "'https://abcde123456ABCDE', 80",
            "'Https://1234566789', 70",
            "'https://abraCadabraundRumpelPumpel', 60",
    })
    void shouldFuzzUri(String s, float percent) {

        fuzzConfig.setPercentOfEach(percent);
        var fuzzerCont = new FuzzerContext(fuzzConfig);
        var org = s;
        var startStr = s.substring(0, 7);
        var fuzzedStr = uriFuzzer.fuzz(s);
        assertNotEquals(org, fuzzedStr);
        assertEquals(startStr, fuzzedStr.substring(0, 7));
    }


    @Test
    void shouldGenerateRandom() {
        assertNotNull(uriFuzzer.generateRandom());
        assertTrue(uriFuzzer.generateRandom().startsWith("https://"));
    }

}