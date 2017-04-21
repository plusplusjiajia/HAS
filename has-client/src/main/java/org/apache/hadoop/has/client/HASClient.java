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

package org.apache.hadoop.has.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.has.common.HASUtil;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.EncAsRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * HAS client
 */
public class HASClient {
    public static final Log LOG = LogFactory.getLog(HASClient.class);
    public static final String AK_ENV_NAME = "AK_CONFIG";

    public TgtTicket requestTgt() throws KrbException {
        String pathName = System.getProperty(AK_ENV_NAME);
        LOG.info("&&& ak path:" + pathName);
        File confDir = new File(pathName);
        AKConfig ak = getAKConfig(confDir);
        String regionId = ak.getString("regionId");
        String accessKeyId = ak.getString("accessKeyId");
        String secret = ak.getString("secret");
        String userName = ak.getString("userName");

        return requestTgt(regionId, accessKeyId, secret, userName);
    }

    /**
     * Request a TGT with user token credential and armor cache
     * @param regionId
     * @param accessKeyId
     * @param secret
     * @param userName
     * @return TGT
     * @throws KrbException e
     */
    public TgtTicket requestTgt(String regionId, String accessKeyId,
                                       String secret, String userName) throws KrbException {
        Client client = Client.create();
        WebResource webResource = client
            .resource("http://localhost:8091/has/v1/welcome?type=ALIYUN&regionId=" + regionId
                + "&accessKeyId=" + accessKeyId
                + "&secret=" + secret
                + "&userName=" + userName);

        ClientResponse response = webResource.accept("application/json")
            .put(ClientResponse.class);

        if (response.getStatus() != 200) {
            throw new RuntimeException("Failed : HTTP error code : "
                + response.getStatus());
        }
        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {

            JSONObject json = response.getEntity(JSONObject.class);

            System.out.println("Output from Server .... \n");
            System.out.println(json);

            return handleResponse(json, accessKeyId, secret);

        } else {
            System.out.println("ERROR! " + response.getStatus());
            System.out.println(response.getEntity(String.class));
            return null;
        }
    }

    public KrbMessage getKrbMessage(JSONObject json) throws KrbException {
        try {
            String type = json.getString("type");
            if (type.equals("ALIYUN")) {
                String krbMessageString = json.getString("krbMessage");
                Base64 base64 = new Base64(0);
                byte[] krbMessage = base64.decode(krbMessageString);
                ByteBuffer byteBuffer = ByteBuffer.wrap(krbMessage);
                KrbMessage kdcRep;
                try {
                    kdcRep = KrbCodec.decodeMessage(byteBuffer);
                } catch (IOException e) {
                    throw new KrbException("Krb decoding message failed", e);
                }
                return kdcRep;
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return null;
    }

    public TgtTicket handleResponse(JSONObject json, String accessKeyId, String secret)
        throws KrbException {
        KrbMessage kdcRep = getKrbMessage(json);

        KrbMessageType messageType = kdcRep.getMsgType();
        if (messageType == KrbMessageType.AS_REP) {
            return processResponse((KdcRep) kdcRep, accessKeyId, secret);
        } else if (messageType == KrbMessageType.TGS_REP) {
            // TODO
        } else if (messageType == KrbMessageType.KRB_ERROR) {
            KrbError error = (KrbError) kdcRep;
            LOG.info("KDC server response with message: "
                + error.getErrorCode().getMessage());

            throw new KrbException(error.getErrorCode(), error.getEtext());
        }
        return null;
    }

    public TgtTicket processResponse(KdcRep kdcRep, String accessKeyId, String secret)
        throws KrbException {

        PrincipalName clientPrincipal = kdcRep.getCname();
        String clientRealm = kdcRep.getCrealm();
        clientPrincipal.setRealm(clientRealm);

        // Get the client to decrypt the EncryptedData
        EncryptionKey clientKey = HASUtil.getClientKey(clientPrincipal.getName(),
            accessKeyId, secret,
            kdcRep.getEncryptedEncPart().getEType());

        byte[] decryptedData = decryptWithClientKey(kdcRep.getEncryptedEncPart(),
                KeyUsage.AS_REP_ENCPART, clientKey);
        if ((decryptedData[0] & 0x1f) == 26) {
            decryptedData[0] = (byte) (decryptedData[0] - 1);
        }
        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        try {
            encKdcRepPart.decode(decryptedData);
        } catch (IOException e) {
            throw new KrbException("Failed to decode EncAsRepPart", e);
        }
        kdcRep.setEncPart(encKdcRepPart);

//        if (getChosenNonce() != encKdcRepPart.getNonce()) {
//            throw new KrbException("Nonce didn't match");
//        }

//        PrincipalName returnedServerPrincipal = encKdcRepPart.getSname();
//        returnedServerPrincipal.setRealm(encKdcRepPart.getSrealm());
//        PrincipalName requestedServerPrincipal = getServerPrincipal();
//        if (requestedServerPrincipal.getRealm() == null) {
//            requestedServerPrincipal.setRealm(getContext().getKrbSetting().getKdcRealm());
//        }
//        if (!returnedServerPrincipal.equals(requestedServerPrincipal)) {
//            throw new KrbException(KrbErrorCode.KDC_ERR_SERVER_NOMATCH);
//        }

//        HostAddresses hostAddresses = getHostAddresses();
//        if (hostAddresses != null) {
//            List<HostAddress> requestHosts = hostAddresses.getElements();
//            if (!requestHosts.isEmpty()) {
//                List<HostAddress> responseHosts = encKdcRepPart.getCaddr().getElements();
//                for (HostAddress h : requestHosts) {
//                    if (!responseHosts.contains(h)) {
//                        throw new KrbException("Unexpected client host");
//                    }
//                }
//            }
//        }

        TgtTicket tgtTicket = getTicket(kdcRep);
        return tgtTicket;

    }

    protected byte[] decryptWithClientKey(EncryptedData data,
                                          KeyUsage usage, EncryptionKey clientKey) throws KrbException {
        if (clientKey == null) {
            throw new KrbException("Client key isn't availalbe");
        }
        return EncryptionHandler.decrypt(data, clientKey, usage);
    }

    /**
     * Get the tgt ticket from KdcRep
     *
     * @param kdcRep
     */
    public TgtTicket getTicket(KdcRep kdcRep) {
        TgtTicket tgtTicket = new TgtTicket(kdcRep.getTicket(),
            (EncAsRepPart) kdcRep.getEncPart(), kdcRep.getCname());
        return tgtTicket;
    }

    /**
     * Get AK configuration
     *
     * @param akConfigFile configuration file
     * @return ak configuration
     */
    public AKConfig getAKConfig(File akConfigFile) throws KrbException {
        if (akConfigFile.exists()) {
            AKConfig akConfig = new AKConfig();
            try {
                akConfig.addIniConfig(akConfigFile);
            } catch (IOException e) {
                throw new KrbException("Can not load the ak configuration file "
                    + akConfigFile.getAbsolutePath());
            }
            return akConfig;
        } else {
             throw new KrbException("Should set the ak.conf");
        }
    }
}