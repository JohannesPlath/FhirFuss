/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ManipulatorsUtilsTest {


    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    @BeforeAll
    static void setup() {
        fuzzConfig = new FuzzConfig();
        fuzzerContext = new FuzzerContext(fuzzConfig);
    }

    @ParameterizedTest
    @CsvSource({
            "50.0f, 10000 ",
            "30.0f, 10000",
            "100f, 10000",
            "5.3f, 10000",
            "25.0f, 35800",
            "5.1f, 10000",
    })
    void shouldRandomize(float percent, int iterations) {
        var fuzzConf = new FuzzConfig();
        fuzzConf.setPercentOfEach(percent);
        var fuzzerCont = new FuzzerContext(fuzzConf);
        int iteration = 0;
        int countTrue = 0;
        for (int x = 0; x < iterations; x++) {
            iteration++;
            var res = fuzzerCont.conditionalChance(percent);
            if (res)
                countTrue++;
        }
        assertTrue(Float.valueOf(iterations) / countTrue >= 100.0f / (percent + 5f));
        assertTrue(Float.valueOf(iteration) / countTrue <= 100.0f / (percent - 5f));
    }





}