/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import java.util.function.Function;

@FunctionalInterface
public interface UnmutableFuzzingMutator<T> extends Function<T, T> {

    T apply(T t);

}

