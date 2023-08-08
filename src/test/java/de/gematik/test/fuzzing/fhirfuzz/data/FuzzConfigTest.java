/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.data;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import lombok.val;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FuzzConfigTest {

    @Test
    void shouldSetupConfCorrect() {
        FuzzConfig fuzzConfig = new FuzzConfig();
        String name = "firstConf";
        fuzzConfig.setName(name);

        float percOfAll = 0.5f;
        float percOfEach = 2.0f;
        fuzzConfig.setPercentOfAll(percOfAll);
        fuzzConfig.setPercentOfEach(percOfEach);
        assertEquals(name, fuzzConfig.getName());
        assertEquals(percOfAll, fuzzConfig.getPercentOfAll());
        assertEquals(percOfEach, fuzzConfig.getPercentOfEach());

    }


    @Test
    void allCouldBeNull() {
        FuzzConfig config = new FuzzConfig();
        assertNull(config.getPercentOfAll());
        assertNull(config.getPercentOfEach());
        assertNull(config.getName());
    }



    @Test
    void getDefaultShouldWork() {
        val fuzzconf = FuzzConfig.getDefault();
        assertNotNull(fuzzconf);

    }

    @Test
    void getRandomShouldWork() {
        val fuzzconf = FuzzConfig.getRandom();
        assertNotNull(fuzzconf);
    }

    @Test
    void toStringShouldWork() {
        val fuzzconf = FuzzConfig.getRandom();
        assertTrue(fuzzconf.toString().length() > 20);
    }

}