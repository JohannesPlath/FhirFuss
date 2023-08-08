/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.IdFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.StringFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.CanonicalType;

import java.util.LinkedList;
import java.util.List;

public class CanonicalTypeFuzzerImpl implements FhirTypeFuzz<CanonicalType> {

    private final FuzzerContext fuzzerContext;

    public CanonicalTypeFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public CanonicalType fuzz(CanonicalType ct) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (val f : m) {
            f.accept(ct);
        }
        return ct;
    }

    private List<FuzzingMutator<CanonicalType>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<CanonicalType>>();
        manipulators.add(this::valueFuzz);
        manipulators.add(this::idFuzz);
        manipulators.add(this::switchValueIdFuzz);
        manipulators.add(this::extFuzz);
        return manipulators;
    }


    private void valueFuzz(CanonicalType ct) {
        StringFuzzImpl stringFuzz = new StringFuzzImpl(fuzzerContext);
        if (!ct.hasValue()) {
            ct.setValue(stringFuzz.generateRandom());
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Value at CanonicalType ", null, ct.getValue()));
        } else {
            val orgEntry = ct.getValue();
            stringFuzz.fuzz(ct::getValue, ct::setValue);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Value at CanonicalType ", orgEntry, "?"));
        }
    }

    private void idFuzz(CanonicalType ct) {
        IdFuzzerImpl idFuzzer = new IdFuzzerImpl(fuzzerContext);
        if (!ct.hasId()) {
            ct.setId(idFuzzer.generateRandom());
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Id at CanonicalType ", null, ct.getId()));
        } else {
            val orgEntry = ct.getValue();
            idFuzzer.fuzz(ct::getId, ct::setId);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz ID at Canonical Profile Entry", orgEntry, "?"));
        }
    }

    private void switchValueIdFuzz(CanonicalType ct) {
        if (ct.hasValue()) {
            val value = ct.getValue();
            val id = ct.getId();
            ct.setValue(id);
            ct.setId(value);
            fuzzerContext.addLog(new FuzzOperationResult<>("switched ID and Value at Canonical Profile Entry", id, value));
        }
    }

    private void extFuzz(CanonicalType ct) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!ct.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            ct.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in CanonicalType", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(ct::getExtension, ct::setExtension);
        }
    }


    public CanonicalType generateRandom() {
        val ct = new CanonicalType();
        ct.setValue(fuzzerContext.getStringFuzz().generateRandom())
                .setExtension(List.of(new ExtensionFuzzerImpl(fuzzerContext).generateRandom()))
                .setId(fuzzerContext.getIdFuzzer().generateRandom());
        return ct;

    }
}
