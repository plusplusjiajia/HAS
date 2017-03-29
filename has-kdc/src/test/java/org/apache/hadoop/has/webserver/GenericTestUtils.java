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

import org.junit.Assert;

import java.io.File;

/**
 * Test provides some very generic helpers which might be used across the tests
 */
public abstract class GenericTestUtils {

  /**
   * system property for test data: {@value}
   */
  public static final String SYSPROP_TEST_DATA_DIR = "test.build.data";

  /**
   * Default path for test data: {@value}
   */
  public static final String DEFAULT_TEST_DATA_DIR =
      "target" + File.separator + "test" + File.separator + "data";

  /**
   * The default path for using in Hadoop path references: {@value}
   */
  public static final String DEFAULT_TEST_DATA_PATH = "target/test/data/";


  /**
   * Get the (created) base directory for tests.
   *
   * @return the absolute directory
   */
  public static File getTestDir() {
    String prop = System.getProperty(SYSPROP_TEST_DATA_DIR, DEFAULT_TEST_DATA_DIR);
    if (prop.isEmpty()) {
      // corner case: property is there but empty
      prop = DEFAULT_TEST_DATA_DIR;
    }
    File dir = new File(prop).getAbsoluteFile();
    dir.mkdirs();
    assertExists(dir);
    return dir;
  }


  /**
   * Assert that a given file exists.
   */
  public static void assertExists(File f) {
    Assert.assertTrue("File " + f + " should exist", f.exists());
  }

}
