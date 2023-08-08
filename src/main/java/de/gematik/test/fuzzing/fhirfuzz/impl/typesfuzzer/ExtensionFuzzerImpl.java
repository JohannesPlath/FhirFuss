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
import org.hl7.fhir.r4.model.BooleanType;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Coding;
import org.hl7.fhir.r4.model.DateType;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.StringType;
import org.hl7.fhir.r4.model.UriType;

import java.util.LinkedList;
import java.util.List;

public class ExtensionFuzzerImpl implements FhirTypeFuzz<Extension> {
    private final FuzzerContext fuzzerContext;

    public ExtensionFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public Extension fuzz(Extension ex) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<Extension> f : m) {
            f.accept(ex);
        }
        return ex;
    }

    public Extension generateRandom() {
        val ex = new Extension();
        ex.setUrl(fuzzerContext.getUrlFuzz().generateRandom())
                .setUrlElement(new UriType(fuzzerContext.getUrlFuzz().generateRandom()))
                .setId(fuzzerContext.getIdFuzzer().generateRandom())
                .setIdElement(new StringType(fuzzerContext.getStringFuzz().generateRandom()));
        return ex;
    }

    private List<FuzzingMutator<Extension>> getMutators() {

        val manipulators = new LinkedList<FuzzingMutator<Extension>>();
        if (getMapContent("TriggertByMedRequest").toLowerCase().matches("true")
                && getMapContent("KBV").toLowerCase().matches("true")) {
            manipulators.add(this::fuzzUrl);
        } else if (getMapContent("TriggertByCoverage").toLowerCase().matches("true")
                && getMapContent("KBV").toLowerCase().matches("true")) {
            manipulators.add(this::fuzzValue);
        } else if (getMapContent("OnlyProfile").toLowerCase().matches("true")) {
            manipulators.add(this::fuzzValue);
        } else if (getMapContent("KBV").toLowerCase().matches("true")) {
            manipulators.add(this::fuzzValue);
        } else {
            manipulators.add(this::fuzzUrl);
            manipulators.add(this::fuzzValue);
            manipulators.add(this::fuzzExt);
            manipulators.add(this::fuzzId);
            manipulators.add(this::fuzzType);
        }

        return manipulators;
    }

    private void fuzzUrl(Extension ex) {
        if (!ex.hasUrl()) {
            val url = fuzzerContext.getUrlFuzz().generateRandom();
            ex.setUrl(url);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Url in Extension ", null, url));
        } else {
            val value = ex.getUrl();
            fuzzerContext.getUrlFuzz().fuzz(ex::getUrl, o -> ex.setUrl(fuzzerContext.getUrlFuzz().fuzz(o)));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzzes URI in Extension ", value, ex.hasValue() ? ex.getValue() : null));
        }
    }

    private void fuzzId(Extension ex) {
        val value = ex.hasId() ? ex.getId() : null;
        fuzzerContext.getIdFuzzer().fuzz(ex::hasId, ex::getId, ex::setId);
        fuzzerContext.addLog(new FuzzOperationResult<>("Changes Id in Extension ", value, ex.hasId() ? ex.getId() : null));
    }

    private void fuzzExt(Extension ex) {
        if (!ex.hasExtension()) {
            val ex2 = this.generateRandom();
            ex.setExtension(List.of(ex2));
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Extension in Extension & Value -> null", null, List.of(ex2)));
        } else {
            val value = ex.getExtension();
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, this);
            listFuzzer.fuzz(ex::getExtension, ex::setExtension);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Extension in Extension ", value, ex.hasUrlElement() ? ex.getUrlElement() : null));
        }
    }

    private void fuzzValue(Extension ex) {
        val value = fuzzerContext.getStringFuzz().generateRandom();
        ex.setValue(new StringType(value));
        fuzzerContext.addLog(new FuzzOperationResult<>("set Value in Extension ", null, value));

    }

    private void fuzzType(Extension ex) {
        if (ex.hasType("CodingType")) {
            for (val e : ex.getExtension()) {
                if (e.getValue() instanceof StringType stringType) {
                    stringType.setValue(fuzzerContext.getStringFuzz().generateRandom());
                } else if (e.getValue() instanceof BooleanType booleanType) {
                    booleanType.setValue((!booleanType.booleanValue()));
                } else if (e.getValue() instanceof DateType dateType) {
                    val dateTypeFuzz = new DateTypeFuzzImpl(fuzzerContext);
                    val org = dateType.getId();
                    dateTypeFuzz.fuzz(dateType);
                    fuzzerContext.addLog(new FuzzOperationResult<>("Changes DateType in Extension ", org, dateType));
                    } else if (e.getValue() instanceof CodeableConcept codeableConcept) {
                        val codingTypeFuzzer = new CodingTypeFuzzerImpl(fuzzerContext);
                        codingTypeFuzzer.fuzz(() -> (Coding) codeableConcept.getCoding(), o -> codeableConcept.setCoding(List.of(o)));
                    }
                }
            }

    }

}
