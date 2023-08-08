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
import org.hl7.fhir.r4.model.Address;
import org.hl7.fhir.r4.model.StringType;

import java.util.LinkedList;
import java.util.List;

public class AddressFuzzerImpl implements FhirTypeFuzz<Address> {
    FuzzerContext fuzzerContext;

    public AddressFuzzerImpl(FuzzerContext fuzzerContext) {
        this.fuzzerContext = fuzzerContext;
    }

    @Override
    public FuzzerContext getContext() {
        return fuzzerContext;
    }

    @Override
    public Address fuzz(Address address) {
        val m = fuzzerContext.getRandomPart(getMutators());
        for (val f : m) {
            f.accept(address);
        }
        return address;
    }

    private List<FuzzingMutator<Address>> getMutators() {
        val manipulators = new LinkedList<FuzzingMutator<Address>>();
        manipulators.add(this::extFuzz);
        manipulators.add(this::periodFuzz);
        manipulators.add(this::countryFuzz);
        manipulators.add(this::cityFuzz);
        manipulators.add(this::postCodeFuzz);
        manipulators.add(this::stateFuzz);
        manipulators.add(this::districtFuzz);
        manipulators.add(this::lineFuzz);
        manipulators.add(this::textFuzz);
        manipulators.add(this::typeFuzz);
        return manipulators;
    }

    public Address generateRandom() {
        return new Address().setUse(fuzzerContext.getRandomOneOfClass(Address.AddressUse.class, Address.AddressUse.NULL))
                .setType(fuzzerContext.getRandomOneOfClass(Address.AddressType.class, Address.AddressType.NULL))
                .setText(fuzzerContext.getStringFuzz().generateRandom())
                .setLine(List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom())))
                .setCity(fuzzerContext.getStringFuzz().generateRandom())
                .setDistrict(fuzzerContext.getStringFuzz().generateRandom())
                .setState(fuzzerContext.getStringFuzz().generateRandom())
                .setPostalCode(fuzzerContext.getStringFuzz().generateRandom())
                .setCountry(fuzzerContext.getStringFuzz().generateRandom())
                .setPeriod(new PeriodFuzzerImpl(fuzzerContext).generateRandom());
    }

    private void typeFuzz(Address a) {
        if (!a.hasType()) {
            val type = fuzzerContext.getRandomOneOfClass(Address.AddressType.class, List.of(Address.AddressType.NULL));
            a.setType(type);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Address :", null, type));
        } else {
            val org = a.getType();
            val newType = fuzzerContext.getRandomOneOfClass(Address.AddressType.class, List.of(org, Address.AddressType.NULL));
            a.setType(newType);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Type in Address :", org, a.hasType() ? a.getType() : null));
        }
    }

    private void textFuzz(Address a) {
        if (!a.hasText()) {
            val txt = fuzzerContext.getStringFuzz().generateRandom();
            a.setText(txt);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Text in Address :", null, txt));
        } else {
            val org = a.getText();
            fuzzerContext.getStringFuzz().fuzz(a::getText, a::setText);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Text in Address :", org, a.hasText() ? a.getText() : null));
        }
    }

    private void lineFuzz(Address a) {
        var stringFuzz = fuzzerContext.getStringFuzz();
        if (!a.hasLine()) {
            val line = List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom()));
            a.setLine(line);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Line in Address :", null, line));
        } else {
            val org = a.getLine().get(0).toString();
            stringFuzz.fuzz(() -> a.getLine().get(0).toString(), o -> a.setLine(List.of(new StringType(o))));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Line in Address :", org, a.hasLine() ? a.getLine().get(0).toString() : null));
        }
    }

    private void cityFuzz(Address a) {
        if (!a.hasCity()) {
            val city = fuzzerContext.getStringFuzz().generateRandom();
            a.setCity(city);
            fuzzerContext.addLog(new FuzzOperationResult<>("set City in Address :", null, city));
        } else {
            val org = a.getCity();
            fuzzerContext.getStringFuzz().fuzz(a::getCity, a::setCity);
            fuzzerContext.addLog(new FuzzOperationResult<>("set City in Address :", org, a.hasCity() ? a.getCity() : null));
        }
    }

    private void districtFuzz(Address a) {
        if (!a.hasDistrict()) {
            val district = fuzzerContext.getStringFuzz().generateRandom();
            a.setDistrict(district);
            fuzzerContext.addLog(new FuzzOperationResult<>("set District in Address :", null, district));
        } else {
            val org = a.getDistrict();
            fuzzerContext.getStringFuzz().fuzz(a::getDistrict, a::setDistrict);
            fuzzerContext.addLog(new FuzzOperationResult<>("set District in Address :", org, a.hasDistrict() ? a.getDistrict() : null));
        }
    }

    private void stateFuzz(Address a) {
        if (!a.hasState()) {
            val state = fuzzerContext.getStringFuzz().generateRandom();
            a.setState(state);
            fuzzerContext.addLog(new FuzzOperationResult<>("set State in Address :", null, state));
        } else {
            val org = a.getState();
            fuzzerContext.getStringFuzz().fuzz(a::getState, a::setState);
            fuzzerContext.addLog(new FuzzOperationResult<>("set State in Address :", org, a.hasState() ? a.getState() : null));
        }
    }

    private void postCodeFuzz(Address a) {
        if (!a.hasPostalCode()) {
            val postal = fuzzerContext.getStringFuzz().generateRandom();
            a.setPostalCode(postal);
            fuzzerContext.addLog(new FuzzOperationResult<>("set PostCode in Address :", null, postal));
        } else {
            val org = a.getPostalCode();
            fuzzerContext.getStringFuzz().fuzz(a::getPostalCode, a::setPostalCode);
            fuzzerContext.addLog(new FuzzOperationResult<>("set PostCode in Address :", org, a.hasPostalCode() ? a.getPostalCode() : null));
        }
    }

    private void countryFuzz(Address a) {
        if (!a.hasCountry()) {
            val county = fuzzerContext.getStringFuzz().generateRandom();
            a.setCountry(county);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Country in Address :", null, county));
        } else {
            val org = a.getCountry();
            fuzzerContext.getStringFuzz().fuzz(a::getCountry, a::setCountry);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Country in Address :", org, a.hasCountry() ? a.getCountry() : null));
        }
    }

    private void periodFuzz(Address a) {
        val periodFuzzer = new PeriodFuzzerImpl(fuzzerContext);
        if (!a.hasPeriod()) {
            val period = periodFuzzer.generateRandom();
            a.setPeriod(period);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Period in Address :", null, period));
        } else {
            val org = a.getPeriod();
            periodFuzzer.fuzz(a::getPeriod, a::setPeriod);
            fuzzerContext.addLog(new FuzzOperationResult<>("set Period in Address :", org, a.hasPeriod() ? a.getPeriod() : null));
        }
    }

    private void extFuzz(Address a) {
        val extensionFuzzer = new ExtensionFuzzerImpl(fuzzerContext);
        if (!a.hasExtension()) {
            val ext = extensionFuzzer.generateRandom();
            a.setExtension(List.of(ext));
            fuzzerContext.addLog(new FuzzOperationResult<>("set Extension in Address", null, ext));
        } else {
            val listFuzzer = new ListFuzzerImpl<>(fuzzerContext, extensionFuzzer);
            listFuzzer.fuzz(a::getExtension, a::setExtension);
        }
    }


}
