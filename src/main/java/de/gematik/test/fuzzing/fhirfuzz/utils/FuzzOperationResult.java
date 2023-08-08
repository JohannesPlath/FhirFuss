/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import static java.text.MessageFormat.format;

public class FuzzOperationResult<T> {
    private final String description;
    private final T orgEntry;
    private final T newEntry;

    public FuzzOperationResult(String description, T orgEntry, T newEntry) {
        this.description = description;
        this.orgEntry = orgEntry;
        this.newEntry = newEntry;
    }

    @Override
    public String toString() {
        return format("{0}: {1} -> {2}", description, orgEntry, newEntry);
    }
}
