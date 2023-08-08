/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import org.hl7.fhir.r4.model.Resource;

/**
 * this Interface has generic implementations in BaseFuzzer
 * concrete implementation in implemented ResourceFuzzerImpl
 * @param <T> restrict the generic Type of BaseFuzzer to Resource
 */
public interface FhirResourceFuzz<T extends Resource> extends BaseFuzzer<T> {


}
