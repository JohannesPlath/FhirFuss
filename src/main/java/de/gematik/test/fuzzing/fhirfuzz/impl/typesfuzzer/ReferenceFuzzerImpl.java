/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.StringFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.UrlFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Reference;

import java.util.LinkedList;
import java.util.List;

public class ReferenceFuzzerImpl implements FhirTypeFuzz<Reference> {
    private final FuzzerContext fuzzerContext;

    public ReferenceFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public Reference fuzz(Reference reference) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Reference> f : m) {
            f.accept(reference);
        }
        return reference;
    }

    private List<FuzzingMutator<Reference>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Reference>>();
        manipulators.add(this::referenceFuzz);
        manipulators.add(this::typeFuzz);
        manipulators.add(this::identFuzz);
        manipulators.add(this::displayFuzz);
        manipulators.add(this::extensionFuzz);
        if (getMapContent("BreakRanges").toLowerCase().matches("true")) {
            manipulators.add(this::breakDisplayLength);
        }
        return manipulators;
    }

    private void referenceFuzz(Reference r) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        if (!r.hasReference()) {
            val url = urlFuzz.generateRandom();
            r.setReference(url);
            fuzzerContext.addLog(new FuzzOperationResult<>("set reference in Reference:", null, url));
        } else {
            val org = r.getReference();

            urlFuzz.fuzz(r::getReference, r::setReference);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz reference in Reference:", org, r.getReference()));
        }
    }


    private void typeFuzz(Reference r) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        if (!r.hasType()) {
            val url = urlFuzz.generateRandom();
            r.setType(url);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Reference:", null, url));
        } else {
            val org = r.getType();
            urlFuzz.fuzz(r::getType, r::setType);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Reference:", org, r.getType()));
        }
    }

    private void identFuzz(Reference r) {
        val identifierFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        if (!r.hasIdentifier()) {
            val ident = identifierFuzzer.generateRandom();
            r.setIdentifier(ident);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Identifier in Reference:", null, ident));
        } else {
            val org = r.getIdentifier().copy();
            identifierFuzzer.fuzz(r::getIdentifier, r::setIdentifier);
        }
    }

    private void displayFuzz(Reference r) {
        val stringFuzzer = new StringFuzzImpl(fuzzerContext);
        if (!r.hasDisplay()) {
            val disp = stringFuzzer.generateRandom();
            r.setDisplay(disp);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Display in Reference:", null, disp));
        } else {
            val disp = r.getDisplay();
            stringFuzzer.fuzz(r::getDisplay, r::setDisplay);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Display in Reference:", disp, r.getDisplay()));
        }
    }

    private void breakDisplayLength(Reference r) {
        if (r.hasDisplay()) {
            val disp = r.getDisplay();
            r.setDisplay(fuzzerContext.getStringFuzz().generateRandom(51));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Displaylength up to 50 in Reference:", disp, r.getDisplay()));
        }
    }

    private void extensionFuzz(Reference r) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!r.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            r.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in Reference", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(r::getExtension, r::setExtension);
        }
    }


    public Reference generateRandom() {
        Reference reference = new Reference();
        val identFuzzer = new IdentifierFuzzerImpl(fuzzerContext);
        return reference.setReference(new UrlFuzzImpl(fuzzerContext).generateRandom())
                .setType(new UrlFuzzImpl(fuzzerContext).generateRandom())
                .setIdentifier(identFuzzer.generateRandom())
                .setDisplay(new StringFuzzImpl(fuzzerContext).generateRandom());
    }
}
