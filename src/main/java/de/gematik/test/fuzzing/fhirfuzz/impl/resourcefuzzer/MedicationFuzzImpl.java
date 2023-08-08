/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirResourceFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.CodeableConceptFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.RatioTypeFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Medication;

import java.util.LinkedList;
import java.util.List;

public class MedicationFuzzImpl implements FhirResourceFuzz<Medication> {
    private final FuzzerContext fuzzerContext;

    public MedicationFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    /**
     * this Medication Fuzzer fuzzes entries anv Values.
     * the intensity could be changed by setting usedPercentOfMutators in fuzzConfig
     *
     * @param med you want to get fuzzed
     * @return the fuzzed med
     */
    @Override
    public Medication fuzz(Medication med) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Medication> f : m) {
            f.accept(med);
        }
        return med;
    }

    private List<FuzzingMutator<Medication>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Medication>>();
        if (getMapContent("KBV").toLowerCase().matches("true")) {
            manipulators.add(this::idFuzz);
            manipulators.add(this::metaFuzz);
            manipulators.add(this::extensionFuzz);
            manipulators.add(this::codeFuzz);
            manipulators.add(this::formFuzz);
            manipulators.add(this::amountFuzz);
        } else {
            manipulators.add(this::identFuzz);
            manipulators.add(this::metaFuzz);
            manipulators.add(this::idFuzz);
            manipulators.add(this::formFuzz);
            manipulators.add(this::extensionFuzz);
            manipulators.add(this::codeFuzz);
            manipulators.add(this::amountFuzz);
            manipulators.add(this::langFuzz);
            manipulators.add(this::statusFuzzer);
        }
        if (getMapContent("BreakRanges").toLowerCase().matches("true")) {
            manipulators.add(this::codeTexFuzz);
        }
        return manipulators;
    }

    private void langFuzz(Medication m) {
        var org = m.hasLanguage() ? m.getLanguage() : null;
        fuzzerContext.getLanguageCodeFuzzer().fuzz(m::hasLanguage, m::getLanguage, m::setLanguage);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Medication", org, m.hasLanguage() ? m.getLanguage() : null));
    }

    private void identFuzz(Medication m) {
        var fhirIdentifierFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        if (!m.hasIdentifier()) {
            val ident = fhirIdentifierFuzzer.generateRandom();
            m.setIdentifier(List.of(ident));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Medication:", null, ident));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, fhirIdentifierFuzzer);
            val ident = m.getIdentifier();
            listFuzzer.fuzz(m::getIdentifier, m::setIdentifier);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Medication:", ident, m.hasIdentifier() ? m.getIdentifier() : null));
        }
    }

    private void metaFuzz(Medication m) {
        fuzzerContext.getFuzzConfig().getDetailSetup().put("OnlyProfile", "TRUE");
        MetaFuzzerImpl metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
        val meta = m.hasMeta() ? m.getMeta() : null;
        metaFuzzer.fuzz(m::hasMeta, m::getMeta, m::setMeta);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Meta in Medication:", meta, m.hasMeta() ? m.getMeta() : null));
        fuzzerContext.getFuzzConfig().getDetailSetup().remove("OnlyProfile");
    }

    private void idFuzz(Medication m) {
        val orgId = m.hasId() ? m.getId() : null;
        fuzzerContext.getIdFuzzer().fuzz(m::hasId, m::getId, m::setId);
        fuzzerContext.addLog(new FuzzOperationResult<>("set ID in Medication:", orgId, m.hasId() ? m.getId() : null));
    }

    private void formFuzz(Medication m) {
        var codConceptFuzz = new CodeableConceptFuzzer(fuzzerContext);
        val orgCoding = m.hasForm() ? m.getForm().copy() : null;
        codConceptFuzz.fuzz(m::hasForm, m::getForm, m::setForm);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Form in Medication:", orgCoding, m.hasForm() ? m.getForm() : null));
    }

    private void extensionFuzz(Medication m) {
        fuzzerContext.getFuzzConfig().getDetailSetup().put("OnlyProfile", "TRUE");
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!m.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            m.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in Medication", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            val org = m.getExtension();
            listFuzzer.fuzz(m::getExtension, m::setExtension);
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in Medication", org, m.hasExtension() ? m.getExtension() : null));
            fuzzerContext.getFuzzConfig().getDetailSetup().remove("OnlyProfile");
        }
    }

    private void codeFuzz(Medication m) {
        val codConceptFuzz = new CodeableConceptFuzzer(fuzzerContext);
        val orgCoding = m.hasCode() ? m.getCode().copy() : null;
        codConceptFuzz.fuzz(m::hasCode, m::getCode, m::setCode);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Code in Medication:", orgCoding, m.hasCode() ? m.getCode() : null));

    }


    private void codeTexFuzz(Medication m) {
        if (m.hasCode()) {
            //KBV profile define max length to 50;
            m.getCode().setText(fuzzerContext.getStringFuzz().generateRandom(52));
        }
    }

    private void amountFuzz(Medication m) {
        val amountFuzz = new RatioTypeFuzzerImpl(fuzzerContext);
        val org = m.hasAmount() ? m.getAmount() : null;
        amountFuzz.fuzz(m::hasAmount, m::getAmount, m::setAmount);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Amount in Medication:", org, m.hasAmount() ? m.getAmount() : null));
    }

    private void statusFuzzer(Medication m) {
        val status = m.hasStatus() ? m.getStatus() : null;
        if (status == null) {
            val newStatus = fuzzerContext.getRandomOneOfClass(Medication.MedicationStatus.class, Medication.MedicationStatus.NULL);
            m.setStatus(newStatus);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Status in Medication:", null, newStatus));
        } else {
            val newStatus = fuzzerContext.getRandomOneOfClass(Medication.MedicationStatus.class, List.of(Medication.MedicationStatus.NULL, status));
            m.setStatus(newStatus);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Status in Medication:", status, newStatus));
        }
    }

    @Override
    public Medication generateRandom() {
        val med = new Medication();
        med.setIdentifier(List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom()));
        med.setMeta(new MetaFuzzerImpl(fuzzerContext).generateRandom());
        med.setId(fuzzerContext.getIdFuzzer().generateRandom());
        med.setForm(new CodeableConceptFuzzer(fuzzerContext).generateRandom());
        med.setExtension(List.of(new ExtensionFuzzerImpl(fuzzerContext).generateRandom()));
        med.setCode(new CodeableConceptFuzzer(fuzzerContext).generateRandom());
        med.setAmount(new RatioTypeFuzzerImpl(fuzzerContext).generateRandom());
        med.setStatus(Medication.MedicationStatus.ACTIVE);
        return med;

    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }
}
