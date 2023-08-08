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
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.StringType;

import java.util.LinkedList;
import java.util.List;

public class HumanNameFuzzerImpl implements FhirTypeFuzz<HumanName> {

    private final FuzzerContext fuzzerContext;

    public HumanNameFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }


    @Override
    public HumanName fuzz(HumanName humanName) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (FuzzingMutator<HumanName> f : m) {
            f.accept(humanName);
        }
        return humanName;
    }


    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    public HumanName generateRandom() {
        return new HumanName()
                .setUse(fuzzerContext.getRandomOneOfClass(HumanName.NameUse.class, HumanName.NameUse.NULL))
                .setText(fuzzerContext.getStringFuzz().generateRandom())
                .setPeriod(new PeriodFuzzerImpl(fuzzerContext).generateRandom())
                .setFamily(fuzzerContext.getStringFuzz().generateRandom(8))
                .setGiven(List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom(8))))
                .setPrefix(List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom(8))))
                .setSuffix(List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom(8))))
                .setPeriod(new PeriodFuzzerImpl(fuzzerContext).generateRandom());
    }

    private List<FuzzingMutator<HumanName>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<HumanName>>();
        manipulators.add(this::fuzzExtension);
        manipulators.add(this::fuzzChanges);
        manipulators.add(this::fuzzFamily);
        manipulators.add(this::fuzzGiven);
        manipulators.add(this::fuzzPrefix);
        manipulators.add(this::fuzzText);
        manipulators.add(this::fuzzSuffix);
        manipulators.add(this::fuzzPeriod);
        return manipulators;
    }

    private void fuzzChanges(HumanName h) {
        if (!h.hasUse()) {
            val nameUse = fuzzerContext.getRandomOneOfClass(HumanName.NameUse.class, HumanName.NameUse.NULL);
            h.setUse(nameUse);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Use in HumanName ", null, nameUse));
        } else {
            val org = h.getUse();
            val newUse = fuzzerContext.getRandomOneOfClass(HumanName.NameUse.class, List.of(org, HumanName.NameUse.NULL));
            h.setUse(newUse);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Use in HumanName ", org, newUse));
        }
    }

    private void fuzzText(HumanName h) {
        if (!h.hasText()) {
            val text = fuzzerContext.getStringFuzz().generateRandom();
            h.setText(text);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Text in HumanName:", null, text));
        } else {
            val text = h.getText();
            fuzzerContext.getStringFuzz().fuzz(h::getText, h::setText);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Text in HumanName:", null, h.hasText() ? h.getText() : null));
        }
    }

    private void fuzzFamily(HumanName h) {
        if (!h.hasFamily()) {
            val fam = fuzzerContext.getStringFuzz().generateRandom(15);
            h.setFamily(fam);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Family in HumanName ", null, fam));
        } else {
            val org = h.getFamily();
            fuzzerContext.getStringFuzz().fuzz(h::getFamily, h::setFamily);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Family in HumanName:", null, h.hasFamily() ? h.getFamily() : null));
        }
    }

    private void fuzzGiven(HumanName h) {
        if (!h.hasGiven()) {
            val giv = fuzzerContext.getStringFuzz().generateRandom(15);
            h.setGiven(List.of(new StringType(giv)));
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Given in HumanName ", null, giv));
        } else {
            val org = h.getGiven().get(0).toString();
            fuzzerContext.getStringFuzz().fuzz(h::getGivenAsSingleString, o -> h.setGiven(List.of(new StringType(o))));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Changes in HumanName:", org, h.hasGiven() ? h.getGivenAsSingleString() : null));
        }
    }

    private void fuzzPrefix(HumanName h) {
        if (!h.hasPrefix()) {
            val pre = fuzzerContext.getStringFuzz().generateRandom(15);
            h.setPrefix(List.of(new StringType(pre)));
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Prefix in HumanName ", null, pre));
        } else {
            val org = h.getPrefixAsSingleString();
            fuzzerContext.getStringFuzz().fuzz(h::getPrefixAsSingleString, o -> h.setPrefix(List.of(new StringType(o))));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Prefix in HumanName:", org, h.hasPrefix() ? h.getPrefixAsSingleString() : null));
        }
    }

    private void fuzzSuffix(HumanName h) {
        if (!h.hasSuffix()) {
            val suf = fuzzerContext.getStringFuzz().generateRandom(15);
            h.setSuffix(List.of(new StringType(suf)));
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Suffix in HumanName ", null, suf));
        } else {
            val org = h.getSuffixAsSingleString();
            fuzzerContext.getStringFuzz().fuzz(h::getSuffixAsSingleString, o -> h.setSuffix(List.of(new StringType(o))));
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Suffix in HumanName:", org, h.hasSuffix() ? h.getSuffixAsSingleString() : null));
        }
    }

    private void fuzzPeriod(HumanName h) {
        PeriodFuzzerImpl periodFuzzer = new PeriodFuzzerImpl(fuzzerContext);
        if (!h.hasPeriod()) {
            periodFuzzer = new PeriodFuzzerImpl(fuzzerContext);
            val per = periodFuzzer.generateRandom();
            h.setPeriod(per);
            fuzzerContext.addLog(new FuzzOperationResult<>("Changes Period in HumanName ", null, per));
        } else {
            val org = h.getPeriod();
            periodFuzzer.fuzz(h::getPeriod, h::setPeriod);
            fuzzerContext.addLog(new FuzzOperationResult<>("fuzz Period in HumanName:", org, h.hasSuffix() ? h.getSuffix() : null));
        }
    }

    private void fuzzExtension(HumanName h) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!h.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            h.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in HumanName", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(h::getExtension, h::setExtension);
        }
    }
}
