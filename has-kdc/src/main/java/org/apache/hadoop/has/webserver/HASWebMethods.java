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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.has.webserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.has.kdc.HASKdcHandler;
import org.apache.hadoop.has.kdc.HASKdcServer;
import org.apache.hadoop.has.webserver.resources.*;
import org.apache.hadoop.http.JettyUtils;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;
import java.util.TreeMap;

/**
 * HAS web methods implementation.
 */

@Path("/welcome")
public class HASWebMethods {
    public static final Log LOG = LogFactory.getLog(HASWebMethods.class);

    private @Context ServletContext context;

    /**
     *
     * @param nameNode
     * @return nameNode.keytab
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response get(@QueryParam(NameNodeParam.NAME) @DefaultValue(NameNodeParam.DEFAULT)
                          final NameNodeParam nameNode) throws Exception {
        if (nameNode.getValue()!=null){
            File file = new File("/etc/hadoop/conf/"+nameNode.getValue()+".keytab");
            if (file.exists()){
                return Response.ok(file).header("Content-Disposition", "attachment; filename=" + file.getName()).build();
            }
        }
        return Response.serverError().build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String post() {
        return "post Welcome to Jersey world";
    }

    /**
     * Handle HTTP PUT request.
     */
    @PUT
    @Produces({MediaType.APPLICATION_OCTET_STREAM + "; " + JettyUtils.UTF_8,
        MediaType.APPLICATION_JSON + "; " + JettyUtils.UTF_8})
    public Response put(
        @QueryParam(TypeParam.NAME) @DefaultValue(TypeParam.DEFAULT)
        final TypeParam type,
           @QueryParam(ReginIdParam.NAME) @DefaultValue(ReginIdParam.DEFAULT)
        final ReginIdParam reginId,
           @QueryParam(AccessKeyIdParam.NAME) @DefaultValue(AccessKeyIdParam.DEFAULT)
        final AccessKeyIdParam accessKeyId,
           @QueryParam(SecretParam.NAME) @DefaultValue(SecretParam.DEFAULT)
        final SecretParam secret,
           @QueryParam(UserNameParam.NAME) @DefaultValue(UserNameParam.DEFAULT)
        final UserNameParam userName,
           @QueryParam(ClientsParam.NAME) @DefaultValue(ClientsParam.DEFAULT)
        final ClientsParam clients
    ) {
        return put(type.getValue(), reginId.getValue(), accessKeyId.getValue(),
            secret.getValue(), userName.getValue(),clients.getValue());
    }

    private Response put(AuthType type, String regionId, String accessKeyId, String secret,
                         String userName,String clients) {
        final HASKdcServer kdcServer = HttpKdcServerImpl.getKdcServerFromContext(context);
        switch (type) {
            case ALIYUN: {

                if (regionId != null && accessKeyId != null && secret != null && userName != null) {
                    HASKdcHandler kdcHandler = new HASKdcHandler(kdcServer);
                    KrbMessage asRep = kdcHandler.getResponse(regionId, accessKeyId, secret, userName);

                    ObjectMapper MAPPER = new ObjectMapper();
                    String js = null;
                    final Map<String, Object> m = new TreeMap<String, Object>();

//JUST FOR DEBUG
//                    AsRep asRep1 = new AsRep();
//                    try {
//                        asRep1.decode(asRep.encode());
//                    } catch (IOException e) {
//                        e.printStackTrace();
//                    }
//                    System.out.println("###client name:" + asRep1.getCname());

                    Base64 base64 = new Base64(0);
                    try {
                        m.put("type", type);
                        m.put("krbMessage", base64.encodeToString(asRep.encode()));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {
                        js = MAPPER.writeValueAsString(m);
                    } catch (JsonProcessingException e) {
                        e.printStackTrace();
                    }
                    return Response.ok(js).type(MediaType.APPLICATION_JSON).build();
                }
                else {
                    return Response.serverError().build();
                }
            }
            case HDFS:{
                if (clients != null){
                    try {
                        File file = kdcServer.addPrincs(clients);
                        return Response.ok(file).header("Content-Disposition", "attachment; filename=hadoop.keytab").build();
//                        return Response.ok("SUCCESS").type(MediaType.TEXT_PLAIN).build();
                    }
                    catch (JSONException e) {
                        e.printStackTrace();
                    }
                    catch (KrbException e){
                        e.printStackTrace();
                    }
                }
                return Response.serverError().build();
            }
            default:
                throw new UnsupportedOperationException(type + " is not supported");
        }
    }
}