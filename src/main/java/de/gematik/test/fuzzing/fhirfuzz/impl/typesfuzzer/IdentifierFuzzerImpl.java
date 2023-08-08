/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.IdFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.StringFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.UrlFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Period;

import java.util.LinkedList;
import java.util.List;

public class IdentifierFuzzerImpl implements FhirTypeFuzz<Identifier> {

    private final FuzzerContext fuzzerContext;


    public IdentifierFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    public Identifier generateRandom() {
        var codingTypeFuzzer = new CodingTypeFuzzerImpl(fuzzerContext);
        Identifier identifier = new Identifier();
        identifier.setUse(fuzzerContext.getRandomOneOfClass(Identifier.IdentifierUse.class, Identifier.IdentifierUse.NULL));
        identifier.setType(codingTypeFuzzer.gerateRandomCodingConcept());
        identifier.setSystem(new UrlFuzzImpl(fuzzerContext).generateRandom());
        identifier.setValue(new StringFuzzImpl(fuzzerContext).generateRandom());
        identifier.setPeriod(new Period().setEnd(fuzzerContext.getRandomDate()));
        return identifier;
    }


    @Override
    public Identifier fuzz(Identifier identifier) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Identifier> f : m) {
            f.accept(identifier);
        }
        return identifier;
    }

    @Override
    public FuzzerContext getContext() {
        return this.fuzzerContext;
    }

    public void fuzz(List<Identifier> identifiers) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (Identifier i : identifiers) {
            fuzz(i);
        }
    }

    private List<FuzzingMutator<Identifier>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Identifier>>();
        /* use */
        manipulators.add(this::useFuzz);
        /* Type */
        manipulators.add(this::typeFuzz);
        /* System */
        manipulators.add(this::urlFuzz);
        /* Value */
        manipulators.add(this::valueFuzz);
        /* Period */
        manipulators.add(this::periodFuzz);
        /* Extension */
        manipulators.add(this::extensionFuzz);
        return manipulators;
    }

    private void useFuzz(Identifier i) {
        if (!i.hasUse()) {
            val entry = (fuzzerContext.getRandomOneOfClass(Identifier.IdentifierUse.class, Identifier.IdentifierUse.NULL));
            i.setUse(entry);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Use in Identifier", null, entry));
        } else {
            var org = i.getUse();
            val newEntry = (fuzzerContext.getRandomOneOfClass(Identifier.IdentifierUse.class, List.of(org, Identifier.IdentifierUse.NULL)));
            i.setUse(newEntry);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Use in Identifier", org, newEntry));
        }
    }

    private void typeFuzz(Identifier i) {
        var codingTypeFuzzer = new CodeableConceptFuzzer(fuzzerContext);
        var org = i.hasType() ? i.getType() : null;
        codingTypeFuzzer.fuzz(i::hasType, i::getType, i::setType);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Identifier", org, i.hasType() ? i.getType() : null));

    }

    private void urlFuzz(Identifier i) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        if (!i.hasSystem()) {
            val newEntry = urlFuzz.generateRandom();
            i.setSystem(newEntry);
            fuzzerContext.addLog(new FuzzOperationResult<>("set System in Identifier", null, newEntry));
        } else {
            var org = i.getSystem();
            urlFuzz.fuzz(i::getSystem, i::setSystem);
            fuzzerContext.addLog(new FuzzOperationResult<>("Fuzz System in Identifier", org, i.hasSystem() ? i.getSystem() : null));
        }
    }

    private void valueFuzz(Identifier i) {
        IdFuzzerImpl idFuzzer = new IdFuzzerImpl(fuzzerContext);
        if (!i.hasValue()) {
            val value = idFuzzer.generateRandom();
            i.setValue(value);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Value in Identifier", null, value));
        } else {
            val org = i.getValue();
            idFuzzer.fuzz(i::getValue, i::setValue);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Value in Identifier", org, i.hasValue() ? i.getValue() : null));
        }
    }

    private void periodFuzz(Identifier i) {
        PeriodFuzzerImpl periodFuzzer = new PeriodFuzzerImpl(fuzzerContext);
        if (!i.hasPeriod()) {
            val newEntry = new Period().setStart(fuzzerContext.getRandomDate());
            i.setPeriod(newEntry);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Period in Identifier", null, newEntry));
        } else {
            val org = i.getPeriod();
            periodFuzzer.fuzz(i::getPeriod, i::setPeriod);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Period in Identifier", org, i.hasPeriod() ? i.getPeriod() : null));
        }
    }

    private void extensionFuzz(Identifier i) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!i.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            i.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in Identifier", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(i::getExtension, i::setExtension);
        }
    }

}
