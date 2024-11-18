/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.httpddosdetector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.commons.logging.Log;
import org.onosproject.httpddosdetector.classifier.randomforest.RandomForest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.lang.Math;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Helpers functions for the HTTP DDos Detector
 */
public class Helpers {

    /**
     * Calculates the standard deviation of a feature.
     * @param sqsum the square sum of the values
     * @param sum the sum of the values
     * @param count the count of the values 
     * @return the standar deviation
     */
    private static Logger log = LoggerFactory.getLogger(RandomForest.class);
    public static float stddev(float sqsum, float sum, long count) {
        if (count < 2) {
            return 0;
        }
        float n = (float) count;
        return (float) Math.sqrt((sqsum - (sum * sum / n)) / (n - 1));
    }

    /**
     * Returns the minimum of two longs
     * @param i1
     * @param i2
     * @return the minimum from i1 and i2
     */
    public static long min(long i1, long i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }

    /**
     * Returns the mininmum of two ints
     * @param i1
     * @param i2
     * @return the minimum from i1 and i2
     */
    public static int min(int i1, int i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }


    public static int mode(ArrayList<Integer> list) {
        if (list == null || list.isEmpty()) {
            throw new IllegalArgumentException("ArrayList must not be null or empty");
        }


        Map<Integer, Integer> frequencyMap = new HashMap<>();
        int maxFrequency = 0;
        int mostFrequentNumber = list.get(0);  // Default to first element
//        log.warn(Arrays.toString(list.toArray()));
        for (int num : list) {
            int frequency = frequencyMap.getOrDefault(num, 0) + 1;
            frequencyMap.put(num, frequency);

            if (frequency > maxFrequency) {
                maxFrequency = frequency;
                mostFrequentNumber = num;
            }

        }
        return mostFrequentNumber;
    }

    /**
     * Get JSON object from file
     *
     * @param filepath target file path
     * @return ObjectNode from file
     */
    public static ObjectNode readJsonFile(String filepath) {
        ObjectNode json = null;
        try (InputStream stream = Helpers.class.getResourceAsStream(filepath))
        {
            //Read JSON file
            ObjectMapper mapper = new ObjectMapper();
            json = (ObjectNode) mapper.readTree(stream);

        } catch (Exception e){
            e.printStackTrace();
        }
        return json;
    }

}