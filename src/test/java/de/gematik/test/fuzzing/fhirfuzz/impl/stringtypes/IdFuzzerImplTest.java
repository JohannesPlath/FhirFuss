/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class IdFuzzerImplTest {

    static FuzzConfig fuzzConfig;
    static FuzzerContext fuzzerContext;
    static IdFuzzerImpl idFuzzer;

    @BeforeAll
    static void setup() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        idFuzzer = new IdFuzzerImpl(fuzzerContext);
    }

    @Test
    void getContext() {
        assertNotNull(idFuzzer.getContext());
    }

    @ParameterizedTest
    @CsvSource({
            "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 50 ",
            "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccccccccccccccccccc,mlknweoiflnkyxlknasdpo90ß32msc.,mpo0.,ascd', 15",
            "'abcde123456ABCDE', 100",
            "'asdsdf345sdfgxd435dfgö,lkj3wq9na', 33",
            "'asd2dgdfg455dfvxcv132123as.däöpüß324e', 45",
            "'asdlkmn231oij4knlasdoi9804nioasdf0asdq3er2134asdweqrihdsknckjhweriughrqwncvfhkewqawe39u14nmksadlkncflkwef093', 15",
    })
    void shouldFuzzString(String s, float percent) {
        fuzzConfig.setPercentOfEach(percent);
        var s2 = idFuzzer.fuzz(s);
        assertNotEquals(s, s2);
    }

    @Test
    void ShoulFuzzIdNull() {
        assertNotNull(idFuzzer.fuzz(null));
    }

    @Test
    void ShouldFuzzId() {
        fuzzConfig.setPercentOfEach(100f);
        val testString = "101.202.303.404.505.606";
        assertNotEquals(testString, idFuzzer.fuzz(testString));

    }

    @Test
    void shouldGenerateRandom() {
        assertNotNull(idFuzzer.generateRandom());
    }

    @Test
    void shouldNotBeNull() {
        assertNotNull(idFuzzer.fuzz(UUID.randomUUID().toString()));
    }

    @ParameterizedTest
    @CsvSource({
            "48c7146c-2564-11ee-be56-0242ac120002",
            "cba6c9e1-4b2f-4aa3-8e73-8be72554afec",
            "29ba5e9d-41a3-458a-8691-64fd2e20474d",
            "57e70287-74fa-413c-9c54-ce7809e70b9e",
            "cadc8e42-2581-11ee-be56-0242ac120002 ",
            "https://www.asd7asd/asd/asd7OIASHNDFALKND87/asädad2ads",
            "https://123456789/abcdefghijklmnopqrstuvwxyz/123456789/" + "abcdefghijklmnopqrstuvwxyz",
            "adsasd234asdca-123asd-123",
    })
    void shouldDetectUUid(String testdaten) {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.f);
        val testString = testdaten;
        val er1 = idFuzzer.fuzz(testdaten);
        assertNotEquals(testString, er1);
        assertNotNull(er1);
    }

}