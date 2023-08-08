/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirResourceFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AddressFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ContactPointFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.ExtensionFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.HumanNameFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.NarrativeTypeFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Practitioner;

import java.util.LinkedList;
import java.util.List;

public class PractitionerFuzzImpl implements FhirResourceFuzz<Practitioner> {
    private final FuzzerContext fuzzerContext;

    public PractitionerFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Practitioner fuzz(Practitioner practitioner) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Practitioner> f : m) {
            f.accept(practitioner);
        }
        return practitioner;
    }

    private List<FuzzingMutator<Practitioner>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Practitioner>>();

        if (getMapContent("KBV").toLowerCase().matches("true")) {
            manipulators.add(this::idFuzz);
            manipulators.add(this::metaFuzz);
            manipulators.add(this::identifyFuzz);
            manipulators.add(this::nameFuzz);
        } else {
            manipulators.add(this::idFuzz);
            manipulators.add(this::langFuzz);
            manipulators.add(this::metaFuzz);
            manipulators.add(this::textFuzz);
            manipulators.add(this::identifyFuzz);
            manipulators.add(this::birthdayFuzz);
            manipulators.add(this::addressFuzz);
            manipulators.add(this::activeFuzz);
            manipulators.add(this::nameFuzz);
            manipulators.add(this::extensionFuzz);
            manipulators.add(this::telecomFuzz);
        }
        return manipulators;
    }


    @Override
    public Practitioner generateRandom() {
        val prac = new Practitioner();
        prac.setId(fuzzerContext.getIdFuzzer().generateRandom());
        prac.setMeta(new MetaFuzzerImpl(fuzzerContext).generateRandom());
        prac.setIdentifier(List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom()));
        prac.setName(List.of(new HumanNameFuzzerImpl(fuzzerContext).generateRandom()));
        return prac;
    }

    private void idFuzz(Practitioner p) {
        val id = p.hasId() ? p.getId() : null;
        fuzzerContext.getIdFuzzer().fuzz(p::hasId, p::getId, p::setId);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Id in Practitioner", id, p.hasId() ? p.getId() : null));
    }

    private void langFuzz(Practitioner p) {
        var org = p.hasLanguage() ? p.getLanguage() : null;
        fuzzerContext.getLanguageCodeFuzzer().fuzz(p::hasLanguage, p::getLanguage, p::setLanguage);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Practitioner", org, p.hasLanguage() ? p.getLanguage() : null));
    }

    private void metaFuzz(Practitioner p) {
        MetaFuzzerImpl metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
        val meta = p.hasMeta() ? p.getMeta() : null;
        metaFuzzer.fuzz(p::hasMeta, p::getMeta, p::setMeta);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Meta in Practitioner", meta, p.hasMeta() ? p.getMeta() : null));
    }

    private void textFuzz(Practitioner p) {
        NarrativeTypeFuzzer typeFuzzer = new NarrativeTypeFuzzer(fuzzerContext);
        val org = p.hasText() ? p.getText() : null;
        typeFuzzer.fuzz(p::hasText, p::getText, p::setText);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Text in Practitioner", org, p.hasText() ? p.getText() : null));
    }

    private void identifyFuzz(Practitioner p) {
        val identifyFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        if (!p.hasIdentifier()) {
            val newIdent = identifyFuzzer.generateRandom();
            p.setIdentifier(List.of(newIdent));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Practitioner", null, newIdent));
        } else {
            val org = p.getIdentifierFirstRep().copy();
            val listFuzz = new ListFuzzerImpl<>(fuzzerContext, identifyFuzzer);
            listFuzz.fuzz(p::getIdentifier, p::setIdentifier);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Identifier in Practitioner:", org, p.hasIdentifier() ? p.getIdentifierFirstRep() : null));
        }
    }

    private void birthdayFuzz(Practitioner p) {
        if (!p.hasBirthDate()) {
            val birth = fuzzerContext.getRandomDate(5);
            p.setBirthDate(birth);
            fuzzerContext.addLog(new FuzzOperationResult<>("set BirthDate in Practitioner", null, birth));
        } else {
            if (fuzzerContext.conditionalChance()) {
                val org = p.getBirthDate();
                p.setBirthDate(null);
                fuzzerContext.addLog(new FuzzOperationResult<>("set BirthDate in Practitioner", org, null));
            } else {
                val org = p.getBirthDate();
                val birth = fuzzerContext.getRandomDate();
                p.setBirthDate(birth);
                fuzzerContext.addLog(new FuzzOperationResult<>("set BirthDate in Practitioner", org, birth));
            }
        }
    }

    private void addressFuzz(Practitioner p) {
        val addressFuzzer = new AddressFuzzerImpl(fuzzerContext);
        if (!p.hasAddress()) {
            val address = addressFuzzer.generateRandom();
            p.setAddress(List.of(address));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Address in Practitioner", null, address));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, addressFuzzer);
            listFuzzer.fuzz(p::getAddress, p::setAddress);
        }
    }

    private void activeFuzz(Practitioner p) {
        if (!p.hasActive()) {
            p.setActive(true);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Practitioner", null, true));
        } else {
            val old = p.getActive();
            val active = !old;
            p.setActive(active);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Practitioner", old, active));
        }
    }

    private void nameFuzz(Practitioner p) {
        HumanNameFuzzerImpl nameFuzzer = new HumanNameFuzzerImpl(fuzzerContext);
        if (!p.hasName()) {
            val hName = nameFuzzer.generateRandom();
            p.setName(List.of(hName));
            fuzzerContext.addLog(new FuzzOperationResult<>("set HumanName 1st Entry in Practitioner", null, hName));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, nameFuzzer);
            listFuzzer.fuzz(p::getName, p::setName);
        }
    }

    private void extensionFuzz(Practitioner p) {
        val extensionFuzz = new ExtensionFuzzerImpl(fuzzerContext);
        if (!p.hasExtension()) {
            val ex = extensionFuzz.generateRandom();
            p.setExtension(List.of(ex));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Extension in Practitioner", null, ex.getUrl()));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzz);
            val org = p.getExtension();
            listFuzzer.fuzz(p::getExtension, p::setExtension);
        }
    }

    private void telecomFuzz(Practitioner p) {
        val contPointFuzz = new ContactPointFuzzImpl(fuzzerContext);
        val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, contPointFuzz);
        val cp = p.hasTelecom() ? p.getTelecom() : null;
        if (cp == null) {
            val newVal = contPointFuzz.generateRandom();
            p.setTelecom(List.of(newVal));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Telecom in Practitioner", null, newVal));
        } else {
            listFuzzer.fuzz(p::getTelecom, p::setTelecom);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Id in Practitioner", cp, p.hasTelecom() ? p.getTelecom() : null));
        }
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }
}
