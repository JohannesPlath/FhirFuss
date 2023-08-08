/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.CodeableConcept;

import java.util.LinkedList;
import java.util.List;

public class CodeableConceptFuzzer implements FhirTypeFuzz<CodeableConcept> {

    final FuzzerContext fuzzerContext;

    public CodeableConceptFuzzer(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;

    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public CodeableConcept fuzz(CodeableConcept cc) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<CodeableConcept> f : m) {
            f.accept(cc);
        }
        return cc;
    }

    private List<FuzzingMutator<CodeableConcept>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<CodeableConcept>>();
        manipulators.add(this::fuzzText);
        manipulators.add(this::fuzzCoding);
        manipulators.add(this::fuzzExtension);
        manipulators.add(this::fuzzId);
        return manipulators;
    }

    private void fuzzText(CodeableConcept cc) {
        if (!cc.hasText()) {
            val txt = fuzzerContext.getStringFuzz().generateRandom();
            cc.setText(txt);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Text in CodeableConcept ", null, txt));
        } else {
            val value = cc.getText();
            fuzzerContext.getStringFuzz().fuzz(cc::getText, cc::setText);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Text in CodeableConcept ", value, cc.hasText() ? cc.getText() : null));
        }
    }

    private void fuzzCoding(CodeableConcept cc) {
        val codingFuzz = new CodingTypeFuzzerImpl(fuzzerContext);
        if (!cc.hasCoding()) {
            val c = codingFuzz.generateRandomCodingList();
            cc.setCoding(c);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Coding in CodeableConcept ", null, c));
        } else {
            val org = cc.getCoding();
            val listFuzz = new ListFuzzerImpl<>(fuzzerContext, codingFuzz);
            listFuzz.fuzz(cc::getCoding, cc::setCoding);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Coding in CodeableConcept ", org, cc.hasCoding() ? cc.getCoding() : null));
        }
    }

    private void fuzzExtension(CodeableConcept cc) {
        val extFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!cc.hasExtension()) {
            val ext = extFuzzer.generateRandom();
            cc.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Extension in CodeableConcept ", null, ext));
        } else {
            val ext = cc.getExtension();
            val listFuzz = new ListFuzzerImpl<>(fuzzerContext, extFuzzer);
            listFuzz.fuzz(cc::getExtension, cc::setExtension);
        }
    }

    private void fuzzId(CodeableConcept cc) {
        if (!cc.hasId()) {
            val id = fuzzerContext.getIdFuzzer().generateRandom();
            cc.setId(id);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Id in CodeableConcept ", null, id));
        } else {
            val id = cc.getId();
            fuzzerContext.getIdFuzzer().fuzz(cc::getId, cc::setId);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Id in CodeableConcept ", id, cc.hasId() ? cc.getId() : null));
        }


    }

    public CodeableConcept generateRandom() {
        return new CodeableConcept().setCoding(new CodingTypeFuzzerImpl(fuzzerContext).generateRandomCodingList()).setText(fuzzerContext.getStringFuzz().generateRandom());
    }


}
