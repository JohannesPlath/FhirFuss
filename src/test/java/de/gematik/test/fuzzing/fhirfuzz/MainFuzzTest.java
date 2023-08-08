/*
 * ${GEMATIK_COPYRIGHT_STATEMENT}
 */

package de.gematik.test.fuzzing.fhirfuzz;

import de.gematik.test.erezept.fhir.util.ResourceUtils;
import lombok.val;
import org.junit.jupiter.api.Test;

class MainFuzzTest {

    String confJson = """
            {"name":"MainFuzzTest Conf",
            "usedPercentOfMutators":100,
            "detailSetup":{"KBV":"True"},
            "percentOfAll":100.0,
            "percentOfEach":100.0,
            "useAllMutators":true,
            "iterations":3,
            "pathToPrintFile":null,
            "shouldPrintToFile":true}""";

    @Test
    void main() {
        val pathToBundle = "fhir/valid/kbv/1.0.2/bundle/5a3458b0-8364-4682-96e2-b262b2ab16eb.xml";
        //val pathToBundle2 = "fhir/valid/kbv/1.1.0/bundle/5a3458b0-8364-4682-96e2-b262b2ab16eb.xml";
        val stringBundle = readFromFile(pathToBundle);
        //val stringBundle2 = readFromFile(pathToBundle2);
        //MainFuzz.main(new String[]{stringBundle, confJson});
        val xmlBundle = MainFuzz.main(new String[]{null, confJson});
        //MainFuzz.main(new String[]{null, null});
    }

    private String readFromFile(String file) {
        return ResourceUtils.readFileFromResource(file);
    }




}