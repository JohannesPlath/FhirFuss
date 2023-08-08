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
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Coding;

import java.util.LinkedList;
import java.util.List;

public class CodingTypeFuzzerImpl implements FhirTypeFuzz<Coding> {
    private final FuzzerContext fuzzerContext;

    public CodingTypeFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public Coding fuzz(Coding c) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Coding> f : m) {
            f.accept(c);
        }
        return c;
    }

    public List<Coding> fuzz(List<Coding> c) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Coding> f : m) {
            for (Coding co : c) {
                f.accept(co);
            }
        }
        return c;
    }

    private List<FuzzingMutator<Coding>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Coding>>();
        manipulators.add(this::fuzzCode);
        manipulators.add(this::fuzzId);
        manipulators.add(this::fuzzExtension);
        manipulators.add(this::fuzzDisplay);
        manipulators.add(this::fuzzUserSel);
        manipulators.add(this::fuzzSystem);
        manipulators.add(this::fuzzVersion);
        return manipulators;
    }

    private void fuzzCode(Coding c) {
        StringFuzzImpl stringFuzz = new StringFuzzImpl(fuzzerContext);
        if (!c.hasCode()) {
            val newCode = stringFuzz.generateRandom(5).toUpperCase();
            c.setCode(newCode);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Code in Coding", null, newCode));
        } else {
            val orgCode = c.getCode();
            stringFuzz.fuzz(c::getCode, c::setCode);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Code in Coding", orgCode, "?"));
        }
    }

    private void fuzzId(Coding c) {
        val stringFuzz = new IdFuzzerImpl(fuzzerContext);
        if (!c.hasId()) {
            val newCode = stringFuzz.generateRandom();
            c.setId(newCode);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Id in Coding", null, newCode));
        } else {
            val orgCode = c.getId();
            stringFuzz.fuzz(c::getId, c::setId);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Id in Coding", orgCode, c.hasId() ? c.getId() : null));
        }
    }

    private void fuzzSystem(Coding c) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        if (!c.hasSystem()) {
            val newSystem = urlFuzz.generateRandom();
            c.setSystem(newSystem);
            fuzzerContext.addLog(new FuzzOperationResult<>("set System in Coding", null, newSystem));
        } else {
            val system = c.getSystem();
            urlFuzz.fuzz(c::getSystem, c::setSystem);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz System in Coding", system, "?"));
        }
    }

    private void fuzzVersion(Coding c) {
        IdFuzzerImpl idFuzzer = new IdFuzzerImpl(fuzzerContext);
        if (!c.hasVersion()) {
            idFuzzer = new IdFuzzerImpl(fuzzerContext);
            val newVersion = idFuzzer.generateRandom();
            c.setVersion(newVersion);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Version in Coding", null, newVersion));
        } else {
            val newVersion = c.getVersion();
            idFuzzer.fuzz(c::getVersion, c::setVersion);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Version in Coding", newVersion, "?"));
        }
    }

    private void fuzzDisplay(Coding c) {
        StringFuzzImpl stringFuzz = new StringFuzzImpl(fuzzerContext);
        if (!c.hasDisplay()) {
            stringFuzz = new StringFuzzImpl(fuzzerContext);
            val newDisplay = stringFuzz.generateRandom();
            c.setDisplay(newDisplay);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Display in Coding", null, newDisplay));
        } else {
            val newDisplay = c.getDisplay();
            stringFuzz.fuzz(c::getDisplay, c::setDisplay);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Display in Coding", newDisplay, "?"));
        }
    }

    private void fuzzUserSel(Coding c) {
        if (!c.hasUserSelected()) {
            val newUserSelect = fuzzerContext.conditionalChance();
            c.setUserSelected(newUserSelect);
            fuzzerContext.addLog(new FuzzOperationResult<>("set UserSelect in Coding", null, newUserSelect));
        } else {
            val userSelected = c.getUserSelected();
            val newUserSelec = !userSelected;
            c.setUserSelected(newUserSelec);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz UserSelect in Coding", userSelected, newUserSelec));
        }
    }

    private void fuzzExtension(Coding c) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!c.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            c.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in UserSelect", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(c::getExtension, c::setExtension);
        }
    }

    public CodeableConcept gerateRandomCodingConcept() {
        var codeConceptList = this.generateRandomCodingList();
        var codeableConcept = new CodeableConcept();
        return codeableConcept.setCoding(codeConceptList);
    }

    public List<Coding> generateRandomCodingList() {
        var coding = generateRandom();
        List<Coding> codeList = new LinkedList<>();
        codeList.add(coding);
        return codeList;
    }

    @Override
    public Coding generateRandom() {
        var coding = new Coding();
        coding.setSystem(new UrlFuzzImpl(fuzzerContext).generateRandom());
        coding.setVersion(new IdFuzzerImpl(fuzzerContext).generateRandom());
        StringFuzzImpl stringFuzz = new StringFuzzImpl(fuzzerContext);
        coding.setCode(stringFuzz.generateRandom(3));
        coding.setDisplay(stringFuzz.generateRandom(100));
        coding.setUserSelected(false);
        coding.setId(fuzzerContext.getIdFuzzer().generateRandom());
        return coding;
    }
}
