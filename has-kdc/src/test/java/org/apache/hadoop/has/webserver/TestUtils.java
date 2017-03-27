/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.has.webserver;

public class TestUtils {
    /**
     * system property for test data: {@value}
     */
    public static final String SYSPROP_TEST_DATA_DIR = "test.build.data";

    /**
     * The default path for using in Hadoop path references: {@value}
     */
    public static final String DEFAULT_TEST_DATA_PATH = "target/test/data/";

    /**
     * Get a temp path. This may or may not be relative; it depends on what the
     * {@link #SYSPROP_TEST_DATA_DIR} is set to. If unset, it returns a path
     * under the relative path {@link #DEFAULT_TEST_DATA_PATH}
     *
     * @param subpath sub path, with no leading "/" character
     * @return a string to use in paths
     */
    public static String getTempPath(String subpath) {
        String prop = System.getProperty(SYSPROP_TEST_DATA_DIR, DEFAULT_TEST_DATA_PATH);
        if (prop.isEmpty()) {
            // corner case: property is there but empty
            prop = DEFAULT_TEST_DATA_PATH;
        }
        if (!prop.endsWith("/")) {
            prop = prop + "/";
        }
        return prop + subpath;
    }
}
