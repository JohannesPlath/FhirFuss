/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.fuzzing.fhirfuzz.utils.FuzzerContext;
import lombok.val;

import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

public interface BaseFuzzer<T> {
    /**
     * Method to fuzz direct a Value
     *
     * @param value
     * @return
     */
    T fuzz(T value);


    default void fuzz(Supplier<T> getter, Consumer<T> setter) {
        if (getContext().conditionalChance()) {
            setter.accept(this.generateRandom());
        } else {
            val a = getter.get();
            val fuzzedOne = this.fuzz(a);
            setter.accept(fuzzedOne);
        }
    }

    default void fuzz(BooleanSupplier checker, Supplier<T> getter, Consumer<T> setter) {
        if (!checker.getAsBoolean()) {
            setter.accept(this.generateRandom());
        } else {
            fuzz(getter, setter);
        }
    }

    default String getMapContent(String key) {
        Map<?, ?> map;
        if (getContext().getFuzzConfig().getDetailSetup() != null &&
                getContext().getFuzzConfig().getDetailSetup().get(key) != null) {
            map = getContext().getFuzzConfig().getDetailSetup();
        } else {
            return "false";
        }
        val erg = map.get(key);
        return erg.toString();
    }

    T generateRandom();

    FuzzerContext getContext();

}
