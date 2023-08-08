/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Period;

import java.util.LinkedList;
import java.util.List;

public class PeriodFuzzerImpl implements FhirTypeFuzz<Period> {
    FuzzerContext fuzzerContext;

    public PeriodFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Period fuzz(Period period) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Period> f : m) {
            f.accept(period);
        }
        return period;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    public Period generateRandom() {
        return new Period()
                .setStart(fuzzerContext.getRandomDate())
                .setEnd(fuzzerContext.getRandomDate());
    }

    private List<FuzzingMutator<Period>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Period>>();
        manipulators.add(
                p -> {
                    if (!p.hasStart()) {
                        val newDate = fuzzerContext.getRandomDate();
                        p.setStart(fuzzerContext.getRandomDate());
                        fuzzerContext.addLog(new FuzzOperationResult<>("set Start in Period:", null, newDate.getTime()));
                    } else if (fuzzerContext.conditionalChance()) {
                        val start = p.getStart();
                        p.setStart(null);
                        fuzzerContext.addLog(new FuzzOperationResult<>("set Start in Period:", start.getTime(), null));
                    } else {
                        val old = p.getStart();
                        val newDate = fuzzerContext.getRandomDate();
                        p.setStart(newDate);
                        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Start in Period:", old.getTime(), newDate.getTime()));
                    }
                });
        manipulators.add(
                p -> {
                    if (!p.hasEnd()) {
                        val newDate = fuzzerContext.getRandomDate();
                        p.setEnd(newDate);
                        fuzzerContext.addLog(new FuzzOperationResult<>("set End in Period:", null, newDate.getTime()));
                    } else if (fuzzerContext.conditionalChance()) {
                        val old = p.getEnd();
                        p.setEnd(null);
                        fuzzerContext.addLog(new FuzzOperationResult<>("set Start in Period:", old.getTime(), null));
                    } else {
                        val old = p.getEnd();
                        val newDate = fuzzerContext.getRandomDate();
                        p.setEnd(newDate);
                        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Start in Period:", old.getTime(), newDate.getTime()));
                    }
                });
        manipulators.add(
                p -> {
                    if (p.hasEnd() && p.hasStart()) {
                        val end = p.getEnd();
                        val start = p.getStart();
                        p.setStart(end);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: newStart", start.getTime(), end.getTime()));
                        p.setEnd(start);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: new End", end.getTime(), start.getTime()));
                    } else if (p.hasStart()) {
                        val start = p.getStart();
                        p.setStart(null);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: newStart", start.getTime(), null));
                        p.setEnd(start);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: new End", null, start.getTime()));
                    } else if (p.hasEnd()) {
                        val end = p.getEnd();
                        p.setStart(end);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: newStart", null, end.getTime()));
                        p.setEnd(null);
                        fuzzerContext.addLog(new FuzzOperationResult<>("switched Start in Period: new End", end.getTime(), null));
                    }
                });
        return manipulators;

    }
}

