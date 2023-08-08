/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class FuzzOperationResultTest {

    @Test
    void shouldBuildWithString() {
        String s1 = "S1";
        String s2 = "S2";
        String s3 = "S3";
        FuzzOperationResult fuzzOperationResult = new FuzzOperationResult<>(s1, s2, s3);
        FuzzOperationResult fuzzOperationResul2 = new FuzzOperationResult<>(s1, null, null);
        assertTrue(fuzzOperationResult.toString().contains(s1));
        assertTrue(fuzzOperationResul2.toString().contains(s1));
    }

    @Test
    void shouldBuildWithInt() {
        String s1 = "S1";
        int s2 = 123;
        int s3 = 123;
        FuzzOperationResult fuzzOperationResult = new FuzzOperationResult<>(s1, s2, s3);
        FuzzOperationResult fuzzOperationResul2 = new FuzzOperationResult<>(s1, null, null);
        assertTrue(fuzzOperationResult.toString().contains(Integer.toString(s2)));
    }

    @Test
    void shouldBuildWithMixed() {
        String s1 = "S1";
        int s2 = 123;
        Float s3 = 123.0f;
        FuzzOperationResult fuzzOperationResult = new FuzzOperationResult<>(s1, s2, s3);
        FuzzOperationResult fuzzOperationResul2 = new FuzzOperationResult<>(s1, null, null);
        assertTrue(fuzzOperationResult.toString().contains(Integer.toString(s2)));
    }


    @Test
    void testToStringWithObjects() {
        FuzzConfig fuzzConfig = new FuzzConfig();
        fuzzConfig.setName("testname");
        FuzzConfig fuzzConfig2 = new FuzzConfig();
        fuzzConfig2.setName("testname2");
        String s1 = "S1";
        FuzzOperationResult fuzzOperationResult = new FuzzOperationResult<>(s1, fuzzConfig, fuzzConfig2);
        assertTrue(fuzzOperationResult.toString().contains("->"));
    }
}