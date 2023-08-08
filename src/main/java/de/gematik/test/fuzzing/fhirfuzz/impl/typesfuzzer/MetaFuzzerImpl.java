/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer;

import de.gematik.test.fuzzing.core.FuzzingMutator;
import de.gematik.test.fuzzing.fhirfuzz.FhirTypeFuzz;
import de.gematik.test.fuzzing.fhirfuzz.impl.ListFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.IdFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.UrlFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzOperationResult;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.CanonicalType;
import org.hl7.fhir.r4.model.Coding;
import org.hl7.fhir.r4.model.DateTimeType;
import org.hl7.fhir.r4.model.InstantType;
import org.hl7.fhir.r4.model.Meta;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class MetaFuzzerImpl implements FhirTypeFuzz<Meta> {

    private final FuzzerContext fuzzerContext;

    public MetaFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public Meta fuzz(Meta meta) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (val f : m) {
            f.accept(meta);
        }
        return meta;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    private List<FuzzingMutator<Meta>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Meta>>();
        manipulators.add(this::fuzzSource);
        manipulators.add(this::fuzzLastUpdate);
        manipulators.add(this::fuzzMeta);
        manipulators.add(this::fuzzProfile);
        manipulators.add(this::fuzzExtension);
        manipulators.add(this::fuzzSecurity);
        manipulators.add(this::fuzzTag);
        manipulators.add(this::fuzzURL);
        return manipulators;
    }

    private void fuzzMeta(Meta m) {
        if (m.hasVersionId()) {
            var id = fuzzerContext.getIdFuzzer().generateRandom();
            m.setVersionId(id);
            fuzzerContext.addLog(new FuzzOperationResult<>("set VersionId in Meta:", null, id));
        } else {
            var org = m.getVersionId();
            fuzzerContext.getIdFuzzer().fuzz(m::getVersionId, m::setVersionId);
            fuzzerContext.addLog(new FuzzOperationResult<>("set VersionId in Meta:", org, m.hasVersionId() ? m.getVersionId() : null));
        }
    }

    private void fuzzURL(Meta m) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        if (!m.hasSource()) {
            val newSource = urlFuzz.generateRandom();
            m.setSource(newSource);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Source in Meta:", null, newSource));
        } else {
            val source = m.getSource();
            urlFuzz.fuzz(m::getSource, m::setSource);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Source in Meta:", source, m.hasSource() ? m.getSource() : null));
        }
    }

    private void fuzzLastUpdate(Meta m) {
        if (!m.hasLastUpdated()) {
            var date = fuzzerContext.getRandomDate();
            m.setLastUpdated(date);
            fuzzerContext.addLog(new FuzzOperationResult<>("set LastUpdate in Meta:", null, date));
        } else if (fuzzerContext.shouldFuzz(m.getLastUpdated())) {
            var orgDate = m.getLastUpdated();
            m.setLastUpdated(null);
            fuzzerContext.addLog(new FuzzOperationResult<>("set LastUpdate in Meta:", orgDate, null));
        } else {
            var orgDate = m.getLastUpdated();
            var newDate = new DateTimeType(fuzzerContext.getRandomDate());
            m.setLastUpdatedElement(new InstantType(newDate));
            fuzzerContext.addLog(new FuzzOperationResult<>("set LastUpdate in Meta:",
                    orgDate, newDate));
        }
    }

    private void fuzzSource(Meta m) {
        if (!m.hasSource()) {
            val newSource = m.getVersionId();
            val newVers = m.getSource();
            m.setSource(newSource);
            m.setVersionId(newVers);
            fuzzerContext.addLog(new FuzzOperationResult<>("switched Source and VersionId in Meta:", newSource, newVers));
        }
    }

    private void fuzzProfile(Meta m) {
        UrlFuzzImpl urlFuzz = new UrlFuzzImpl(fuzzerContext);
        val cnonicalTypeFuzz = new CanonicalTypeFuzzerImpl(fuzzerContext);
        if (!m.hasProfile()) {
            val canonicalType = cnonicalTypeFuzz.generateRandom();
            List<CanonicalType> profiles = new LinkedList<>();
            profiles.add(canonicalType);
            m.setProfile(profiles);
            var res = profiles.stream().map(Object::toString).collect(Collectors.joining("\n"));

            fuzzerContext.addLog(new FuzzOperationResult<>(
                    "set Profile in Meta:",
                    null,
                    res));
        } else {
            var listFuzz = new ListFuzzerImpl<>(fuzzerContext, cnonicalTypeFuzz);
            var prof = m.getProfile();
            cnonicalTypeFuzz.fuzz(() -> m.getProfile().get(0), o -> m.setProfile(List.of(o)));
            fuzzerContext.addLog(new FuzzOperationResult<>("switched Source and VersionId in Meta:", prof, "new "));
        }
    }

    private void fuzzSecurity(Meta m) {
        CodingTypeFuzzerImpl codingTypeFuzzerImpl = new CodingTypeFuzzerImpl(fuzzerContext);
        if (m.getSecurity() == null) {
            var codingList = codingTypeFuzzerImpl.generateRandomCodingList();
            var coding = codingList.get(0);
            m.setSecurity(codingList);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Security in Meta:", null,
                    coding.getSystem() + " " + coding.getVersion() + " " + coding.getCode() + " " + coding.getDisplay() + " " + coding.getUserSelected()));
        } else {
            var listFuzz = new ListFuzzerImpl<>(fuzzerContext, codingTypeFuzzerImpl);
            var sec = m.getSecurity();
            listFuzz.fuzz(m::getSecurity, m::setSecurity);

        }
    }

    private void fuzzTag(Meta m) {
        CodingTypeFuzzerImpl codingTypeFuzzerImpl = new CodingTypeFuzzerImpl(fuzzerContext);
        if (m.getTag() == null) {
            var codingList = codingTypeFuzzerImpl.generateRandomCodingList();
            var coding = codingList.get(0);
            m.setTag(codingList);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Security in Meta:", null,
                    coding.getSystem() + " " + coding.getVersion() + " " + coding.getCode() + " " + coding.getDisplay() + " " + coding.getUserSelected()));
        } else {
            var sec = m.getTag();
            for (Coding c : sec) {
                codingTypeFuzzerImpl.fuzz(c);
            }
        }
    }

    private void fuzzExtension(Meta m) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!m.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            m.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("Extension in Meta", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(m::getExtension, m::setExtension);
        }
    }

    public Meta generateRandom() {
        Meta meta = new Meta();
        val idfuzzer = new IdFuzzerImpl(fuzzerContext);
        val urlFuzzer = new UrlFuzzImpl(fuzzerContext);
        meta.setVersionId(idfuzzer.generateRandom());
        meta.setLastUpdated(fuzzerContext.getRandomDate());
        meta.setSource(urlFuzzer.generateRandom());
        meta.setId(idfuzzer.generateRandom());
        CanonicalType canonicalType = new CanonicalType(urlFuzzer.generateRandom());
        List<CanonicalType> profiles = List.of(canonicalType);
        meta.setProfile(profiles);
        return meta;
    }
}
