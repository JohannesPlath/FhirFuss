/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LanguageCodeFuzzerImplTest {

    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static LanguageCodeFuzzerImpl languageFuzzer;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        languageFuzzer = new LanguageCodeFuzzerImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);

    }

    @Test
    void getContext() {
        assertNotNull(languageFuzzer.getContext());
    }

    @Test
    void fuzz() {
        String teststring = "askjhasdnkb2qiuoehaksnc kajhawdi";
        val res = languageFuzzer.fuzz(teststring);
        assertNotEquals(teststring, languageFuzzer.fuzz(teststring));
    }

    @Test
    void generateRandom() {
        assertNotNull(languageFuzzer.generateRandom());
        assertTrue(languageFuzzer.generateRandom().length() >= 2);
    }
    //todo Reduce
    /*@Test
    void shouldGenerateRandom(){
        for (int i = 0; i <  100 ; i++){
            val org = languageFuzzer.generateRandom();
            System.out.println("org -> " + languageFuzzer.fuzz(org));
        }

    }*/
}