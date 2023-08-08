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
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.NarrativeTypeFuzzer;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Organization;

import java.util.LinkedList;
import java.util.List;

public class OrganisationFuzzImpl implements FhirResourceFuzz<Organization> {
    private final FuzzerContext fuzzerContext;

    public OrganisationFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Organization fuzz(Organization org) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Organization> f : m) {
            f.accept(org);
        }
        return org;
    }

    @Override
    public Organization generateRandom() {
        val org = new Organization();
        org.setId(fuzzerContext.getIdFuzzer().generateRandom());
        org.setMeta(new MetaFuzzerImpl(fuzzerContext).generateRandom());
        org.setLanguage(fuzzerContext.getLanguageCodeFuzzer().generateRandom());
        org.setText(new NarrativeTypeFuzzer(fuzzerContext).generateRandom());
        org.setExtension(List.of(new ExtensionFuzzerImpl(fuzzerContext).generateRandom()));
        org.setIdentifier(List.of(new IdentifierFuzzerImpl(fuzzerContext).generateRandom()));
        org.setName(fuzzerContext.getStringFuzz().generateRandom(15));
        org.setTelecom(List.of(new ContactPointFuzzImpl(fuzzerContext).generateRandom()));
        org.setAddress(List.of(new AddressFuzzerImpl(fuzzerContext).generateRandom()));
        return org;
    }

    private List<FuzzingMutator<Organization>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Organization>>();
        manipulators.add(this::idFuzz);
        manipulators.add(this::metaFuzz);
        manipulators.add(this::identifyFuzz);
        manipulators.add(this::langFuzz);
        manipulators.add(this::activeFuzz);
        manipulators.add(this::textFuzz);
        manipulators.add(this::nameFuzz);
        manipulators.add(this::addressFuzz);
        manipulators.add(this::extensionFuzz);
        manipulators.add((this::telcomFuzz));
        return manipulators;
    }

    private void telcomFuzz(Organization o) {
        val contPointFuzz = new ContactPointFuzzImpl(fuzzerContext);
        val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, contPointFuzz);
        val cp = o.hasTelecom() ? o.getTelecom() : null;
        if (cp == null) {
            val newVal = contPointFuzz.generateRandom();
            o.setTelecom(List.of(newVal));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Telecom in Organization", null, newVal));
        } else {
            listFuzzer.fuzz(o::getTelecom, o::setTelecom);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Id in Organization", cp, o.hasTelecom() ? o.getTelecom() : null));
        }
    }

    private void idFuzz(Organization o) {
        val id = o.hasId() ? o.getId() : null;
        fuzzerContext.getIdFuzzer().fuzz(o::hasId, o::getId, o::setId);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzzed Id in Organization", id, o.hasId() ? o.getId() : null));
    }

    private void metaFuzz(Organization o) {
        MetaFuzzerImpl metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
        val meta = o.hasMeta() ? o.getMeta() : null;
        metaFuzzer.fuzz(o::hasMeta, o::getMeta, o::setMeta);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Meta in Organization", meta, o.hasMeta() ? o.getMeta() : null));

    }

    private void identifyFuzz(Organization o) {
        val identifyFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        if (!o.hasIdentifier()) {
            val newIdent = identifyFuzzer.generateRandom();
            o.setIdentifier(List.of(newIdent));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Organization", null, newIdent));
        } else {
            val org = o.getIdentifierFirstRep().copy();
            val listFuzz = new ListFuzzerImpl<>(fuzzerContext, identifyFuzzer);
            listFuzz.fuzz(o::getIdentifier, o::setIdentifier);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Identifier in Organization:", org, o.hasIdentifier() ? o.getIdentifierFirstRep() : null));
        }
    }

    private void langFuzz(Organization o) {
        var org = o.hasLanguage() ? o.getLanguage() : null;
        fuzzerContext.getLanguageCodeFuzzer().fuzz(o::getLanguage, o::setLanguage);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Organization", org, o.hasLanguage() ? o.getLanguage() : null));
    }

    private void activeFuzz(Organization o) {
        if (!o.hasActive()) {
            o.setActive(true);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Organization", null, true));
        } else {
            val old = o.getActive();
            val active = !old;
            o.setActive(active);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Organization", old, active));
        }
    }

    private void textFuzz(Organization o) {
        NarrativeTypeFuzzer typeFuzzer = new NarrativeTypeFuzzer(fuzzerContext);
        val org = o.hasText() ? o.getText() : null;
        typeFuzzer.fuzz(o::hasText, o::getText, o::setText);
        fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Text in Organization", org, o.hasText() ? o.getText() : null));

    }

    private void nameFuzz(Organization o) {
        val org = o.hasName() ? o.getName() : null;
        fuzzerContext.getStringFuzz().fuzz(o::getName, o::setName);
        fuzzerContext.addLog(new FuzzOperationResult<>("Name  in Organization", org, o.hasName() ? o.getName() : null));

    }


    private void extensionFuzz(Organization o) {
        val extensionFuzz = new ExtensionFuzzerImpl(fuzzerContext);
        if (!o.hasExtension()) {
            val ex = extensionFuzz.generateRandom();
            o.setExtension(List.of(ex));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Extension in Organization", null, ex.getValue()));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzz);
            val org = o.getExtension();
            listFuzzer.fuzz(o::getExtension, o::setExtension);
        }
    }

    private void addressFuzz(Organization o) {
        val addressFuzzer = new AddressFuzzerImpl(fuzzerContext);
        if (!o.hasAddress()) {
            val address = addressFuzzer.generateRandom();
            o.setAddress(List.of(address));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Address in Organization", null, address));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, addressFuzzer);
            listFuzzer.fuzz(o::getAddress, o::setAddress);
        }
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }
}
