/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.impl.typefuzzer;

import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.IdFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.StringFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.stringtypes.UrlFuzzImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.AddressFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.impl.typesfuzzer.PeriodFuzzerImpl;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzConfig;
import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;
import org.hl7.fhir.r4.model.Address;
import org.hl7.fhir.r4.model.StringType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AddressFuzzerImplTest {
    private static FuzzConfig fuzzConfig;
    private static FuzzerContext fuzzerContext;

    private static AddressFuzzerImpl addressFuzzer;
    private static IdFuzzerImpl idFuzzer;
    private static UrlFuzzImpl urlFuzz;
    private static StringFuzzImpl stringFuzz;
    private Address address;

    @BeforeAll
    static void setUpConf() {
        fuzzConfig = new FuzzConfig();
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        fuzzConfig.setUseAllMutators(true);
        fuzzerContext = new FuzzerContext(fuzzConfig);
        addressFuzzer = new AddressFuzzerImpl(fuzzerContext);
        idFuzzer = new IdFuzzerImpl(fuzzerContext);
        urlFuzz = new UrlFuzzImpl(fuzzerContext);
        stringFuzz = new StringFuzzImpl(fuzzerContext);
    }

    @BeforeEach
    void setupComp() {
        fuzzConfig.setPercentOfEach(100.0f);
        fuzzConfig.setPercentOfAll(100.0f);
        address = new Address();
    }

    @Test
    void getContext() {
        assertNotNull(addressFuzzer.getContext());
    }

    @Test
    void generateRandom() {
        assertNotNull(addressFuzzer.generateRandom());
    }

    @Test
    void shouldFuzzType() {
        assertFalse(address.hasType());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasType());

        val test = fuzzerContext.getRandomOneOfClass(Address.AddressType.class, Address.AddressType.NULL);
        address.setType(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getType());
    }

    @Test
    void shouldFuzzText() {
        assertFalse(address.hasText());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasText());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setText(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getText());
    }

    @Test
    void shouldFuzzLine() {
        assertFalse(address.hasLine());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasLine());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = List.of(new StringType(fuzzerContext.getStringFuzz().generateRandom(150)));
        address.setLine(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test.get(0).getValue(), address.getLine().get(0).getValue());
    }

    @Test
    void shouldFuzzCity() {
        assertFalse(address.hasCity());
        fuzzConfig.setPercentOfAll(00.0f);
        addressFuzzer.fuzz(address);
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setCity(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getCountry());
    }

    @Test
    void shouldFuzzDistrict() {
        assertFalse(address.hasDistrict());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasDistrict());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setDistrict(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getDistrict());
    }

    @Test
    void shouldFuzzState() {
        assertFalse(address.hasState());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasState());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setState(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getState());
    }

    @Test
    void shouldFuzzPostal() {
        assertFalse(address.hasPostalCode());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasPostalCode());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setPostalCode(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getPostalCode());
    }

    @Test
    void shouldFuzzCountry() {
        assertFalse(address.hasCountry());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasCountry());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = stringFuzz.generateRandom(150);
        address.setCountry(test);
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test, address.getCountry());
    }

    @Test
    void shouldFuzzPeriod() {
        assertFalse(address.hasPeriod());
        addressFuzzer.fuzz(address);
        assertTrue(address.hasPeriod());
        fuzzConfig.setPercentOfAll(100.0f);
        addressFuzzer.fuzz(address);
        val test = new PeriodFuzzerImpl(fuzzerContext).generateRandom();
        address.setPeriod(test.copy());
        fuzzConfig.setPercentOfAll(0.00f);
        addressFuzzer.fuzz(address);
        assertNotEquals(test.getEnd().getTime(), address.getPeriod().getEnd().getTime());
    }

}