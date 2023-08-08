/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AnnotationTypeFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Annotation;
import org.hl7.fhir.r4.model.StringType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnnotationTypeFuzzImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static AnnotationTypeFuzzImpl annotationTypeFuzz;
    private Annotation annotation;


    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        annotationTypeFuzz = new AnnotationTypeFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        annotation = new Annotation();
    }

    @Test
    void shouldFuzzText() {
        assertFalse(annotation.hasText());
        annotationTypeFuzz.fuzz(annotation);
        assertTrue(annotation.hasText());
        annotationTypeFuzz.fuzz(annotation);
        val testObject = fuzzerContext.getStringFuzz().generateRandom(15);
        annotation.setText(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        annotationTypeFuzz.fuzz(annotation);
        assertNotEquals(testObject, annotation.getText());
    }

    @Test
    void fuzzTime() {
        assertFalse(annotation.hasTime());
        annotationTypeFuzz.fuzz(annotation);
        assertTrue(annotation.hasTime());
        annotationTypeFuzz.fuzz(annotation);
        val testObject = fuzzerContext.getRandomDate();
        annotation.setTime(testObject);
        fuzzConfig.setPercentOfAll(0.00f);
        annotationTypeFuzz.fuzz(annotation);
        assertNotEquals(testObject, annotation.getTime());

    }

    @Test
    void shouldFuzzAuth() {
        assertFalse(annotation.hasAuthor());
        annotationTypeFuzz.fuzz(annotation);
        assertTrue(annotation.hasAuthor());
        annotationTypeFuzz.fuzz(annotation);
        val testObject = fuzzerContext.getStringFuzz().generateRandom(15);
        annotation.setAuthor(new StringType(testObject));
        fuzzConfig.setPercentOfAll(0.00f);
        annotationTypeFuzz.fuzz(annotation);
        assertNotEquals(testObject, annotation.getAuthor());
    }

    @Test
    void generateRandom() {
        assertNotNull(annotationTypeFuzz.generateRandom());
    }

    @Test
    void getContext() {
        assertNotNull(annotationTypeFuzz.getContext());
    }
}