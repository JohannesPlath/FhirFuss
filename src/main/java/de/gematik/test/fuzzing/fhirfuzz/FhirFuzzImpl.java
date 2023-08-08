/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.erezept.fhir.builder.kbv.KbvErpBundleBuilder;
import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.CompositionFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.CoverageFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.MedicationFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.MedicationRequestFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.OrganisationFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.PatientFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.resourcefuzzer.PractitionerFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.IdentifierFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.MetaFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Composition;
import org.hl7.fhir.r4.model.Coverage;
import org.hl7.fhir.r4.model.Medication;
import org.hl7.fhir.r4.model.MedicationRequest;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Practitioner;
import org.hl7.fhir.r4.model.ResourceType;

import java.util.LinkedList;
import java.util.List;

@Slf4j
public class FhirFuzzImpl implements FhirResourceFuzz<Bundle> {
    private final FuzzerContext fuzzerContext;

    public FhirFuzzImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public Bundle generateRandom() {
        return KbvErpBundleBuilder.faker().build();
    }


    private List<FuzzingMutator<Bundle>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Bundle>>();
        manipulators.add(this::idFuzz);
        manipulators.add(this::identifyFuzz);
        manipulators.add(this::typeFuzz);
        manipulators.add(this::metaFuzz);
        manipulators.add(this::langFuzz);
        return manipulators;
    }

    @Override
    public Bundle fuzz(Bundle orgBundle) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Bundle> f : m) {
            f.accept(orgBundle);
        }

        val entry = orgBundle.getEntry();
        for (Bundle.BundleEntryComponent e : entry) {
            if (e.getResource().getResourceType() == ResourceType.Composition && e.getResource() instanceof Composition composition) {
                val fhirResourceFuzz = new CompositionFuzzImpl(fuzzerContext);
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(composition)))
                    fhirResourceFuzz.fuzz(composition);
            }
            if (e.getResource().getResourceType() == ResourceType.Patient && e.getResource() instanceof Patient patient) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(patient)))
                    new PatientFuzzerImpl(fuzzerContext).fuzz(patient);
            }
            if (e.getResource().getResourceType() == ResourceType.Bundle && e.getResource() instanceof Bundle bundle && Boolean.TRUE.equals(fuzzerContext.shouldFuzz(bundle))) {
                log.info("Bundle has Bundle as entry and will be called recursive !!!");
                this.fuzz(bundle);

            }
            if (e.getResource().getResourceType() == ResourceType.Medication && e.getResource() instanceof Medication medication) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(medication)))
                    new MedicationFuzzImpl(fuzzerContext).fuzz(medication);

            }
            if (e.getResource().getResourceType() == ResourceType.MedicationRequest && e.getResource() instanceof MedicationRequest medicationR) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(medicationR)))
                    new MedicationRequestFuzzImpl(fuzzerContext).fuzz(medicationR);

            }
            if (e.getResource().getResourceType() == ResourceType.Coverage && e.getResource() instanceof Coverage coverage) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(coverage)))
                    new CoverageFuzzImpl(fuzzerContext).fuzz(coverage);

            }
            if (e.getResource().getResourceType() == ResourceType.Practitioner && e.getResource() instanceof Practitioner practitioner) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(practitioner)))
                    new PractitionerFuzzImpl(fuzzerContext).fuzz(practitioner);
            }
            if (e.getResource().getResourceType() == ResourceType.Organization && e.getResource() instanceof Organization organization) {
                if (Boolean.TRUE.equals(fuzzerContext.shouldFuzz(organization)))
                    new OrganisationFuzzImpl(fuzzerContext).fuzz(organization);
            }

        }
        return orgBundle;
    }

    private void idFuzz(Bundle b) {
        val orgId = b.hasId() ? b.getId() : null;
        fuzzerContext.getIdFuzzer().fuzz(b::hasId, b::getId, b::setId);
        fuzzerContext.addLog(new FuzzOperationResult<>("set ID in Bundle:", orgId, b.hasId() ? b.getId() : null));
    }

    private void identifyFuzz(Bundle b) {
        var fhirIdentifierFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        val ident = b.hasIdentifier() ? b.getIdentifier() : null;
        fhirIdentifierFuzzer.fuzz(b::hasIdentifier, b::getIdentifier, b::setIdentifier);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Bundle:", ident, b.hasIdentifier() ? b.getIdentifier() : null));
    }

    private void typeFuzz(Bundle b) {
        if (!b.hasType()) {
            val type = fuzzerContext.getRandomOneOfClass(Bundle.BundleType.class, Bundle.BundleType.NULL);
            b.setType(type);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Bundle:", null, type));
        } else {
            val org = b.getType();
            val newType = fuzzerContext.getRandomOneOfClass(Bundle.BundleType.class, List.of(org, Bundle.BundleType.NULL));
            b.setType(newType);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Type in Bundle:", org, newType));
        }
    }

    private void metaFuzz(Bundle b) {
        MetaFuzzerImpl metaFuzzer = new MetaFuzzerImpl(fuzzerContext);
        val meta = b.hasMeta() ? b.getMeta() : null;
        metaFuzzer.fuzz(b::hasMeta, b::getMeta, b::setMeta);
        fuzzerContext.addLog(new FuzzOperationResult<>("set Meta in Bundle:", meta, b.hasMeta() ? b.getMeta() : null));
    }

    private void langFuzz(Bundle b) {
        if (!b.hasLanguage()) {
            val lang = fuzzerContext.getLanguageCodeFuzzer().generateRandom();
            b.setLanguage(lang);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Bundle:", null, lang));
        } else {
            val lang = b.getLanguage();
            fuzzerContext.getLanguageCodeFuzzer().fuzz(b::getLanguage, b::setLanguage);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Language in Bundle:", lang, b.hasLanguage() ? b.getLanguage() : null));
        }
    }

}
