/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import org.hl7.fhir.r4.model.Type;
/**
 * this Interface has generic implementations in BaseFuzzer
 * concrete implementation in implemented TypeFuzzerImpl
 * @param <T> restrict the generic Type of BaseFuzzer to Type
 */
public interface FhirTypeFuzz<T extends Type> extends BaseFuzzer<T> {


}
