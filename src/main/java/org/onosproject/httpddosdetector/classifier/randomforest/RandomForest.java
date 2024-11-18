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
package org.onosproject.httpddosdetector.classifier.randomforest;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.LoggerFactory;
import org.onosproject.httpddosdetector.Helpers;
import org.onosproject.httpddosdetector.flow.parser.FlowData;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomForest {
    private static Logger log = LoggerFactory.getLogger(RandomForest.class);

    public boolean isLoaded = false;
    public ArrayList<RandomTree> trees;

    /**
     * Loads the model to be used for the classification
     *
     * @param json JsonNode the array of trees to be used in the classification
     */
    public void Load(JsonNode json){
        if(json != null && json.isArray()){
            // Iterate over tree array and parse it
            trees = new ArrayList<RandomTree>();
            json.forEach( treeData -> { 
                RandomTree t = new RandomTree();
                t.Load(treeData);
                trees.add(t);
            } );
            isLoaded = true;
        } else {
            log.error("Couldn't load json into random forest because json is not an array");
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(FlowData f) {
        ArrayList<Integer> predictions = new ArrayList<Integer>();
        for(int i = 0; i < trees.size(); i++){
            int prediction = trees.get(i).Classify(f.ToArrayList());
            predictions.add(prediction);
        }
        long countOnes = predictions.stream().filter(x -> x == 1).count();

        // Kiểm tra nếu số lượng số 1 lớn hơn 15 thì trả về 1, nếu không thì trả về 0
        return countOnes > 15 ? 1 : 0;
//        log.warn("1: " + Arrays.toString(predictions.toArray()));
//        int test = Helpers.mode(predictions);
//        log.warn("2: " + String.valueOf(test));
    }
}