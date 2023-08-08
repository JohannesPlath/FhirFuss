/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz.utils;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static java.text.MessageFormat.format;

@Slf4j
@Getter
@Setter
public class FuzzConfig {
    private String name;
    private Float usedPercentOfMutators;
    private Map<String, String> detailSetup;
    private Float percentOfAll;
    private Float percentOfEach;
    private Boolean useAllMutators;
    private int iterations;
    private String pathToPrintFile;
    private Boolean shouldPrintToFile;


    public static FuzzConfig getDefault() {
        val fuzzConf = new FuzzConfig();
        fuzzConf.name = "default";
        fuzzConf.usedPercentOfMutators = 40.00f;
        fuzzConf.percentOfAll = 20.00f;
        fuzzConf.percentOfEach = 10.00f;
        fuzzConf.useAllMutators = false;
        fuzzConf.iterations = 3;
        fuzzConf.shouldPrintToFile = false;
        fuzzConf.setDetailSetup(new HashMap<>());
        fuzzConf.getDetailSetup().put("KBV", "TRUE");
        fuzzConf.getDetailSetup().put("BreakRanges", "TRUE");
        return fuzzConf;
    }

    public static FuzzConfig getRandom() {
        val fuzzConf = new FuzzConfig();
        Random random = new SecureRandom();
        fuzzConf.setDetailSetup(new HashMap<>());
        fuzzConf.getDetailSetup().put("KBV", "TRUE");
        fuzzConf.getDetailSetup().put("BreakRanges", "TRUE");
        fuzzConf.usedPercentOfMutators = random.nextFloat(50);
        fuzzConf.percentOfAll = random.nextFloat(20);
        fuzzConf.percentOfEach = random.nextFloat(20);
        fuzzConf.useAllMutators = false;
        fuzzConf.iterations = random.nextInt(5);
        fuzzConf.shouldPrintToFile = false;
        log.info(format("FuzzConfig called: {6}, Attributes had been setup default with following entries: " +
                        "PercentOfMutators: {0}, PercentOfAll: {1}, PercentOfEach: {2}, UseAllMutators: {3}, Iterations: {4}, ShouldPrintToFIle: {5}, specific SetupDetails: {7}",
                fuzzConf.usedPercentOfMutators, fuzzConf.percentOfAll, fuzzConf.percentOfEach, fuzzConf.useAllMutators, fuzzConf.iterations, fuzzConf.shouldPrintToFile, fuzzConf.name, fuzzConf.detailSetup));
        return fuzzConf;
    }


    @Override
    public String toString() {
        return format("FuzzConfig called: {6}: " +
                        "PercentOfMutators: {0}, PercentOfAll: {1}, PercentOfEach: {2}, UseAllMutators: {3}, ShouldPrintToFIle: {5}, specific SetupDetails: {7}",
                this.usedPercentOfMutators, this.percentOfAll, this.percentOfEach, this.useAllMutators, this.iterations, this.shouldPrintToFile, this.name, this.detailSetup);

    }
}
