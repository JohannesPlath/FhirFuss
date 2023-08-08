/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FuzzerContextTest {
    static FuzzerContext fuzzerContext;


    @BeforeAll
    static void setup() {
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.00F);
        fuzzConfig.setPercentOfEach(100.00f);
        fuzzerContext = new FuzzerContext(fuzzConfig);
    }

    @Test
    void generateFakeLong() {
        assertNotNull(fuzzerContext.generateFakeLong());
        assertTrue(fuzzerContext.generateFakeLong() >= 0L);

        //dateTimeType.get
    }


    @Test
    void conditionalChance() {
        var res = fuzzerContext.conditionalChance(100.0f);
        assertTrue(res);
        var res2 = fuzzerContext.conditionalChance(0.0f);
        assertFalse(res2);

    }

    @Test
    void testRandom() {
        int counter = 0;
        for (int i = 0; i < 10000; i++) {
            val res = (int) fuzzerContext.getRandom().nextFloat(2f);
            if (res > 0) counter++;
        }
        System.out.println("Counter: " + counter);
    }

    @Test
    void shouldGetRandomTime() {
        assertNotNull(fuzzerContext.getRandomDate());

    }
}