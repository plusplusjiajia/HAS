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
package org.apache.hadoop.has.webserver.resources;

import org.apache.hadoop.fs.XAttrSetFlag;

import java.util.EnumSet;

public class XAttrSetFlagParam extends EnumSetParam<XAttrSetFlag> {
  /** Parameter name. */
  public static final String NAME = "flag";
  /** Default parameter value. */
  public static final String DEFAULT = "";

  private static final Domain<XAttrSetFlag> DOMAIN = new Domain<>(
      NAME, XAttrSetFlag.class);

  public XAttrSetFlagParam(final EnumSet<XAttrSetFlag> flag) {
    super(DOMAIN, flag);
  }

  /**
   * Constructor.
   * @param str a string representation of the parameter value.
   */
  public XAttrSetFlagParam(final String str) {
    super(DOMAIN, DOMAIN.parse(str));
  }

  @Override
  public String getName() {
    return NAME;
  }

  public EnumSet<XAttrSetFlag> getFlag() {
    return getValue();
  }
}