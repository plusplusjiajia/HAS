/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.hadoop.service;

import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.aliyuncs.sts.model.v20150401.AssumeRoleRequest;
import com.aliyuncs.sts.model.v20150401.AssumeRoleResponse;

public class StsService {

  public static final String REGION_CN_HANGZHOU = "cn-hangzhou";
  public static final String STS_API_VERSION = "2015-04-01";

  static AssumeRoleResponse assumeRole(String accessKeyId, String accessKeySecret,
                                       String roleArn, String roleSessionName, String policy,
                                       ProtocolType protocolType) throws ClientException {
    try {
      // 创建一个 Aliyun Acs Client, 用于发起 OpenAPI 请求
      IClientProfile profile = DefaultProfile.getProfile(REGION_CN_HANGZHOU, accessKeyId, accessKeySecret);
      DefaultAcsClient client = new DefaultAcsClient(profile);
      // 创建一个 AssumeRoleRequest 并设置请求参数
      final AssumeRoleRequest request = new AssumeRoleRequest();
      request.setVersion(STS_API_VERSION);
      request.setMethod(MethodType.POST);
      request.setProtocol(protocolType);
      request.setRoleArn(roleArn);
      request.setRoleSessionName(roleSessionName);
      request.setPolicy(policy);
      // 发起请求，并得到response
      final AssumeRoleResponse response = client.getAcsResponse(request);
      return response;
    } catch (ClientException e) {
      throw e;
    }
  }

  public static void main(String[] args) {
    // setting the proxy
    String host = "child-prc.intel.com";
    String port = "913";
    System.setProperty("http.proxyHost", host);
    System.setProperty("http.proxyPort", port);
    System.setProperty("https.proxyHost", host);
    System.setProperty("https.proxyPort", port);
    // 只有 RAM用户（子账号）才能调用 AssumeRole 接口
    // 阿里云主账号的AccessKeys不能用于发起AssumeRole请求
    // 请首先在RAM控制台创建一个RAM用户，并为这个用户创建AccessKeys
    String accessKeyId = "***";
    String accessKeySecret = "***";
    // AssumeRole API 请求参数: RoleArn, RoleSessionName, Policy, and DurationSeconds
    // RoleArn 需要在 RAM 控制台上获取
    String roleArn = "acs:ram::1206289646325268:role/role1";
    // RoleSessionName 是临时Token的会话名称，自己指定用于标识你的用户，主要用于审计，或者用于区分Token颁发给谁
    // 但是注意RoleSessionName的长度和规则，不要有空格，只能有'-' '_' 字母和数字等字符
    // 具体规则请参考API文档中的格式要求
    String roleSessionName = "alice-001";
    // 如何定制你的policy?
    String policy = "{\n" +
      "    \"Version\": \"1\", \n" +
      "    \"Statement\": [\n" +
      "        {\n" +
      "            \"Action\": [\n" +
      "                \"oss:GetBucket\", \n" +
      "                \"oss:GetObject\" \n" +
      "            ], \n" +
      "            \"Resource\": [\n" +
      "                \"acs:oss:*:*:*\"\n" +
      "            ], \n" +
      "            \"Effect\": \"Allow\"\n" +
      "        }\n" +
      "    ]\n" +
      "}";
    // 此处必须为 HTTPS
    ProtocolType protocolType = ProtocolType.HTTPS;
    try {
      final AssumeRoleResponse response = assumeRole(accessKeyId, accessKeySecret,
        roleArn, roleSessionName, policy, protocolType);
      System.out.println("Expiration: " + response.getCredentials().getExpiration());
      System.out.println("Access Key Id: " + response.getCredentials().getAccessKeyId());
      System.out.println("Access Key Secret: " + response.getCredentials().getAccessKeySecret());
      System.out.println("Security Token: " + response.getCredentials().getSecurityToken());
    } catch (ClientException e) {
      System.out.println("Failed to get a token.");
      System.out.println("Error code: " + e.getErrCode());
      System.out.println("Error message: " + e.getErrMsg());
    }
  }
}
