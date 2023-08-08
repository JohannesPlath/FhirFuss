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
import static org.junit.jupiter.api.Assertions.assertNull;

class StringFuzzImplTest {
    static FuzzConfig fuzzConfig;
    static FuzzerContext fuzzerContext;
    static StringFuzzImpl stringFuzzer;

    @BeforeAll
    static void setup() {
        fuzzConfig = new FuzzConfig();
        fuzzerContext = new FuzzerContext(fuzzConfig);
        stringFuzzer = new StringFuzzImpl(fuzzerContext);
    }

    @Test
    void getContext() {
        assertNotNull(stringFuzzer.getContext());
    }


    @ParameterizedTest
    @CsvSource({
            "'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 40 ",
            "'Http://www.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccccccccccc,mlknweoiflnkyxlknasdpo90ß32msc.,mpo0.,ascd', 15",
            "'https://abcde123456ABCDE', 80",
            "'Https://1234566789', 70",
            "'https://abraCadabraundRumpelPumpel', 60",
    })
    void shouldFuzz(String s, float percent) {
        fuzzConfig.setPercentOfEach(percent);
        var org = s;
        var fuzzedStr = stringFuzzer.fuzz(s);
        assertNotEquals(org, fuzzedStr);
    }

    @ParameterizedTest
    @CsvSource({
            "'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0 ",
            "'Http://www.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccccccccccc,mlknweoiflnkyxlknasdpo90ß32msc.,mpo0.,ascd', 0",
            "'https://abcde123456ABCDE', 0",
            "'Https://1234566789', 0",
            "'https://abraCadabraundRumpelPumpel', 0",
    })
    void shouldNotFuzz(String s, float percent) {
        fuzzConfig.setPercentOfEach(percent);
        var org = s;
        var fuzzedStr = stringFuzzer.fuzz(s);
        assertEquals(org, fuzzedStr);
    }

    @Test
    void shouldNotFuzz() {
        assertNull(stringFuzzer.fuzz(null));
    }

    @Test
    void shouldNotThrowExceptionAtNull() {
        var fuzzConf = new FuzzConfig();
        fuzzConf.setPercentOfEach(15.0f);
        var resp = stringFuzzer.fuzz(null);
        assertNull(resp);
    }

    @Test
    void shouldGenerateRandom() {
        assertNotNull(stringFuzzer.generateRandom(150));
    }
}