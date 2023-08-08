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
import org.hl7.fhir.r4.model.Dosage;

import java.util.LinkedList;
import java.util.List;

public class DosageFuzzImpl implements FhirTypeFuzz<Dosage> {

    private final FuzzerContext fuzzerContext;

    public DosageFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Dosage fuzz(Dosage dosage) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (val f : m) {
            f.accept(dosage);
        }
        return dosage;
    }

    private List<FuzzingMutator<Dosage>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Dosage>>();
        manipulators.add(this::sequenceFuzzer);
        manipulators.add(this::textFuzzer);
        manipulators.add(this::additionalInstrFuzz);
        manipulators.add(this::patientInstructFuzzer);
        manipulators.add(this::siteFuzzer);
        manipulators.add(this::routeFuzzer);
        manipulators.add(this::methodFuzzer);
        manipulators.add(this::dosePerPeriodFuzzer);
        manipulators.add(this::dosePerAdmin);
        manipulators.add(this::dosePerLife);
        return manipulators;
    }

    private void sequenceFuzzer(Dosage d) {
        val org = d.hasSequence() ? d.getSequence() : null;
        fuzzerContext.getIntFuzz().fuzz(d::hasSequence, d::getSequence, d::setSequence);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Sequence in Dosage", org, d.hasSequence() ? d.getSequence() : null));
    }

    private void textFuzzer(Dosage d) {
        val org = d.hasText() ? d.getText() : null;
        fuzzerContext.getStringFuzz().fuzz(d::hasText, d::getText, d::setText);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Text in Dosage", org, d.hasText() ? d.getText() : null));
    }

    private void patientInstructFuzzer(Dosage d) {
        val org = d.hasPatientInstruction() ? d.getPatientInstruction() : null;
        fuzzerContext.getStringFuzz().fuzz(d::hasPatientInstruction, d::getPatientInstruction, d::setPatientInstruction);
        fuzzerContext.addLog(new FuzzOperationResult<>("set PatientInstruction in Dosage", org, d.hasPatientInstruction() ? d.getPatientInstruction() : null));
    }


    private void additionalInstrFuzz(Dosage d) {
        var codConceptFuzz = new CodeableConceptFuzzer(fuzzerContext);
        val cat = d.hasAdditionalInstruction() ? d.getAdditionalInstructionFirstRep() : null;
        if (cat == null) {
            val newEntry = codConceptFuzz.generateRandom();
            d.setAdditionalInstruction(List.of(newEntry));
            fuzzerContext.addLog(new FuzzOperationResult<>("Set AdditionalInstruction in Dosage:", null, newEntry));
        } else {
            val listFuzz = new ListFuzzerImpl<>(fuzzerContext, codConceptFuzz);
            val orgCoding = d.hasAdditionalInstruction() ? d.getAdditionalInstructionFirstRep() : null;
            listFuzz.fuzz(d::getAdditionalInstruction, d::setAdditionalInstruction);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz AdditionalInstruction in Dosage:", orgCoding, d.hasAdditionalInstruction() ? d.getAdditionalInstructionFirstRep() : null));
        }
    }

    private void siteFuzzer(Dosage d) {
        var codingTypeFuzzer = new CodeableConceptFuzzer(fuzzerContext);
        var org = d.hasSite() ? d.getSite().getCodingFirstRep() : null;
        codingTypeFuzzer.fuzz(d::hasSite, d::getSite, d::setSite);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Site in Dosage", org, d.hasSite() ? d.getSite().getCodingFirstRep() : null));
    }

    private void routeFuzzer(Dosage d) {
        var codingTypeFuzzer = new CodeableConceptFuzzer(fuzzerContext);
        var org = d.hasRoute() ? d.getRoute().getCodingFirstRep() : null;
        codingTypeFuzzer.fuzz(d::hasRoute, d::getRoute, d::setRoute);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Route in Dosage", org, d.hasRoute() ? d.getRoute().getCodingFirstRep() : null));
    }

    private void methodFuzzer(Dosage d) {
        var codingTypeFuzzer = new CodeableConceptFuzzer(fuzzerContext);
        var org = d.hasMethod() ? d.getMethod().getCodingFirstRep() : null;
        codingTypeFuzzer.fuzz(d::hasMethod, d::getMethod, d::setMethod);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Method in Dosage", org, d.hasMethod() ? d.getMethod().getCodingFirstRep() : null));
    }

    private void dosePerPeriodFuzzer(Dosage d) {
        val ratioFuzz = new RatioTypeFuzzerImpl(fuzzerContext);
        val org = d.hasMaxDosePerPeriod() ? d.getMaxDosePerPeriod() : null;
        ratioFuzz.fuzz(d::hasMaxDosePerPeriod, d::getMaxDosePerPeriod, d::setMaxDosePerPeriod);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz MaxDosePerPeriod in Dosage", org, d.hasMaxDosePerPeriod() ? d.getMaxDosePerPeriod() : null));

    }

    private void dosePerAdmin(Dosage d) {
        val smplQauntityFuzz = new SimpleQuantityImpl(fuzzerContext);
        val dose = d.hasMaxDosePerAdministration() ? d.getMaxDosePerAdministration() : null;
        smplQauntityFuzz.fuzz(d::hasMaxDosePerAdministration, d::getMaxDosePerAdministration, d::setMaxDosePerAdministration);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz MaxDosePerAdministration in Dosage", dose, d.hasMaxDosePerAdministration() ? d.getMaxDosePerAdministration() : null));
    }

    private void dosePerLife(Dosage d) {
        val smplQauntityFuzz = new SimpleQuantityImpl(fuzzerContext);
        val dose = d.hasMaxDosePerLifetime() ? d.getMaxDosePerLifetime() : null;
        smplQauntityFuzz.fuzz(d::hasMaxDosePerLifetime, d::getMaxDosePerLifetime, d::setMaxDosePerLifetime);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz MaxDosePerLifetime in Dosage", dose, d.hasMaxDosePerLifetime() ? d.getMaxDosePerLifetime() : null));
    }

    @Override
    public Dosage generateRandom() {
        return new Dosage()
                .setSequence(fuzzerContext.getRandom().nextInt())
                .setText(fuzzerContext.getStringFuzz().generateRandom())
                .setAdditionalInstruction(List.of(new CodeableConceptFuzzer(fuzzerContext).generateRandom()))
                .setPatientInstruction(fuzzerContext.getStringFuzz().generateRandom())
                //.setTiming() todo Implmenet TimingFuzzImpl
                .setSite(new CodeableConceptFuzzer(fuzzerContext).generateRandom())
                .setRoute(new CodeableConceptFuzzer(fuzzerContext).generateRandom())
                .setMethod(new CodeableConceptFuzzer(fuzzerContext).generateRandom());
        //.addDoseAndRate();
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }
}
