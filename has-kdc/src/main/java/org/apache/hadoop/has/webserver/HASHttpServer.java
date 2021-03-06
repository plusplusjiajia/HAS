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

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.http.HttpConfig;
import org.apache.hadoop.http.HttpServer2;
import org.apache.hadoop.net.NetUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;

/**
 * Encapsulates the HTTP server started by the HAS KDC.
 */
@InterfaceAudience.Private
public class HASHttpServer {

  public static final Log LOG = LogFactory.getLog(HASHttpServer.class.getName());
  private HttpServer2 httpServer;
  private final Configuration conf;

  private InetSocketAddress httpAddress;
  private InetSocketAddress httpsAddress;
  private final InetSocketAddress bindAddress;


  HASHttpServer(Configuration conf, InetSocketAddress bindAddress) {
    this.conf = conf;
    this.bindAddress = bindAddress;
  }

  private void init(Configuration conf) throws IOException {

    final String pathSpec = "/has/v1/*";
    // add has packages
    httpServer.addJerseyResourcePackage(HASHttpServer.class
        .getPackage().getName(),
        pathSpec);
  }

  /**
   * Get http policy.
   */
  public static HttpConfig.Policy getHttpPolicy(Configuration conf) {
    String policyStr = conf.get(HASConfigKeys.HAS_HTTP_POLICY_KEY,
        HASConfigKeys.HAS_HTTP_POLICY_DEFAULT);
    HttpConfig.Policy policy = HttpConfig.Policy.fromString(policyStr);
    if (policy == null) {
      throw new HadoopIllegalArgumentException("Unregonized value '"
          + policyStr + "' for " + HASConfigKeys.HAS_HTTP_POLICY_KEY);
    }

    conf.set(HASConfigKeys.HAS_HTTP_POLICY_KEY, policy.name());
    return policy;
  }

  /**
   * Return a HttpServer.Builder that the ssm can use to
   * initialize their HTTP / HTTPS server.
   */
  public static HttpServer2.Builder httpServerTemplateForHAS(
          Configuration conf, final InetSocketAddress httpAddr,
          final InetSocketAddress httpsAddr, String name) throws IOException {
    HttpConfig.Policy policy = getHttpPolicy(conf);
    HttpServer2.Builder builder = new HttpServer2.Builder().setName(name);
    if (policy.isHttpEnabled()) {
      if (httpAddr.getPort() == 0) {
        builder.setFindPort(true);
      }
      URI uri = URI.create("http://" + NetUtils.getHostPortString(httpAddr));
      builder.addEndpoint(uri);
      LOG.info("Starting Web-server for " + name + " at: " + uri);
    }

    if (policy.isHttpsEnabled() && httpsAddr != null) {
      Configuration sslConf = loadSslConfiguration(conf);
      loadSslConfToHttpServerBuilder(builder, sslConf);

      if (httpsAddr.getPort() == 0) {
        builder.setFindPort(true);
      }

      URI uri = URI.create("https://" + NetUtils.getHostPortString(httpsAddr));
      builder.addEndpoint(uri);
      LOG.info("Starting Web-server for " + name + " at: " + uri);
    }

    return builder;
  }

    /**
   * Load HTTPS-related configuration.
   */
  public static Configuration loadSslConfiguration(Configuration conf) {
    Configuration sslConf = new Configuration(false);

    sslConf.addResource(conf.get(
        HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY,
        HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_DEFAULT));

    final String[] reqSslProps = {
        HASConfigKeys.HAS_SERVER_HTTPS_TRUSTSTORE_LOCATION_KEY,
        HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_LOCATION_KEY,
        HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_PASSWORD_KEY,
        HASConfigKeys.HAS_SERVER_HTTPS_KEYPASSWORD_KEY
    };

    // Check if the required properties are included
    for (String sslProp : reqSslProps) {
      if (sslConf.get(sslProp) == null) {
        LOG.warn("SSL config " + sslProp + " is missing. If " +
            HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY +
            " is specified, make sure it is a relative path");
      }
    }

    boolean requireClientAuth = conf.getBoolean(HASConfigKeys.HAS_CLIENT_HTTPS_NEED_AUTH_KEY,
        HASConfigKeys.HAS_CLIENT_HTTPS_NEED_AUTH_DEFAULT);
    sslConf.setBoolean(HASConfigKeys.HAS_CLIENT_HTTPS_NEED_AUTH_KEY, requireClientAuth);
    return sslConf;
  }

  public static HttpServer2.Builder loadSslConfToHttpServerBuilder(HttpServer2.Builder builder,
                                                                   Configuration sslConf) {
    return builder
        .needsClientAuth(
            sslConf.getBoolean(HASConfigKeys.HAS_CLIENT_HTTPS_NEED_AUTH_KEY,
                HASConfigKeys.HAS_CLIENT_HTTPS_NEED_AUTH_DEFAULT))
        .keyPassword(getPassword(sslConf, HASConfigKeys.HAS_SERVER_HTTPS_KEYPASSWORD_KEY))
        .keyStore(sslConf.get("ssl.server.keystore.location"),
            getPassword(sslConf, HASConfigKeys.HAS_SERVER_HTTPS_KEYSTORE_PASSWORD_KEY),
            sslConf.get("ssl.server.keystore.type", "jks"))
        .trustStore(sslConf.get("ssl.server.truststore.location"),
            getPassword(sslConf, HASConfigKeys.HAS_SERVER_HTTPS_TRUSTSTORE_PASSWORD_KEY),
            sslConf.get("ssl.server.truststore.type", "jks"))
        .excludeCiphers(
            sslConf.get("ssl.server.exclude.cipher.list"));
  }

  /**
   * Leverages the Configuration.getPassword method to attempt to get
   * passwords from the CredentialProvider API before falling back to
   * clear text in config - if falling back is allowed.
   *
   * @param conf  Configuration instance
   * @param alias name of the credential to retreive
   * @return String credential value or null
   */
  static String getPassword(Configuration conf, String alias) {
    String password = null;
    try {
      char[] passchars = conf.getPassword(alias);
      if (passchars != null) {
        password = new String(passchars);
      }
    } catch (IOException ioe) {
      LOG.warn("Setting password to null since IOException is caught"
          + " when getting password", ioe);

      password = null;
    }
    return password;
  }

  /**
   * for information related to the different configuration options and
   * Http Policy is decided.
   */
  void start() throws IOException {
    HttpConfig.Policy policy = getHttpPolicy(conf);
    final String infoHost = bindAddress.getHostName();

    final InetSocketAddress httpAddr = bindAddress;

    final String httpsAddrString = conf.getTrimmed(
        HASConfigKeys.HAS_HTTPS_ADDRESS_KEY,
        HASConfigKeys.HAS_HTTPS_ADDRESS_DEFAULT);
    InetSocketAddress httpsAddr = NetUtils.createSocketAddr(httpsAddrString);

    if (httpsAddr != null) {
      // If DFS_NAMENODE_HTTPS_BIND_HOST_KEY exists then it overrides the
      // host name portion of DFS_NAMENODE_HTTPS_ADDRESS_KEY.
      final String bindHost =
          conf.getTrimmed(HASConfigKeys.HAS_HTTPS_BIND_HOST_KEY);
      if (bindHost != null && !bindHost.isEmpty()) {
        httpsAddr = new InetSocketAddress(bindHost, httpsAddr.getPort());
      }
    }

    HttpServer2.Builder builder = httpServerTemplateForHAS(conf, httpAddr, httpsAddr, "has");

    httpServer = builder.build();

    init(conf);

    httpServer.start();
    int connIdx = 0;
    if (policy.isHttpEnabled()) {
      httpAddress = httpServer.getConnectorAddress(connIdx++);
      conf.set(HASConfigKeys.HAS_HTTP_ADDRESS_KEY,
          NetUtils.getHostPortString(httpAddress));
    }

    if (policy.isHttpsEnabled()) {
      httpsAddress = httpServer.getConnectorAddress(connIdx);
      conf.set(HASConfigKeys.HAS_HTTPS_ADDRESS_KEY,
          NetUtils.getHostPortString(httpsAddress));
    }

  }

  /**
   * Joins the httpserver.
   */
  public void join() throws InterruptedException {
    if (httpServer != null) {
      httpServer.join();
    }
  }

  void stop() throws Exception {
    if (httpServer != null) {
      httpServer.stop();
    }
  }

  InetSocketAddress getHttpAddress() {
    return httpAddress;
  }

  InetSocketAddress getHttpsAddress() {
    return httpsAddress;
  }

  /**
   * Returns the httpServer.
   * @return HttpServer2
   */
  @VisibleForTesting
  public HttpServer2 getHttpServer() {
    return httpServer;
  }
}
