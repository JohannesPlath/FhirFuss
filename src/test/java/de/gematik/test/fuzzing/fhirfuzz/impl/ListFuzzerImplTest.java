/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodingTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Coding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ListFuzzerImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;
    private static ListFuzzerImpl listFuzzer;
    private static CodingTypeFuzzerImpl codingTypeFuzzer;

    Coding coding;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        codingTypeFuzzer = new CodingTypeFuzzerImpl(fuzzerContext);
        listFuzzer = new ListFuzzerImpl<>(fuzzerContext, codingTypeFuzzer);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        coding = new Coding();
    }

    @Test
    void getContext() {
        assertNotNull(listFuzzer.getContext());
    }

    @Test
    void fuzz() {
        val cod = codingTypeFuzzer.generateRandomCodingList();
        cod.add(codingTypeFuzzer.generateRandom());
        cod.add(codingTypeFuzzer.generateRandom());
        listFuzzer.fuzz(cod);
        assertNotNull(cod);
    }

}