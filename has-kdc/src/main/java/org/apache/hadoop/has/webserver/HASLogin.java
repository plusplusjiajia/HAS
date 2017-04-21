package org.apache.hadoop.has.webserver;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.has.kdc.HASKdcServer;
import org.apache.hadoop.has.webserver.resources.PrincipalParam;
import org.apache.kerby.kerberos.kerb.client.JaasKrbUtil;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletContext;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * HAS login API.
 */
@Path("/login")
public class HASLogin {
    public static final Log LOG = LogFactory.getLog(HASLogin.class);
    private @Context ServletContext context;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String loginUsingKeytab(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                       final PrincipalParam principal) {
        File keytabFile = new File("/etc/hadoop/conf/hadoop.keytab");
        System.out.println("principla : " + principal.getValue());
        Set<Principal> principals = new HashSet();
        principals.add(new KerberosPrincipal(principal.getValue()));
        Subject subject = new Subject(false, principals, new HashSet(), new HashSet());
        Configuration conf = JaasKrbUtil.useKeytab(principal.getValue(), keytabFile);
        String confName = "KeytabConf";

        try {
            LoginContext loginContext = new LoginContext(confName, subject, (CallbackHandler)null, conf);
            loginContext.login();
//            JaasKrbUtil.loginUsingKeytab(principal.getValue(),keytabFile);
            return "SUCCESS";
        } catch (LoginException e) {
            e.printStackTrace();
            return "Faild cause by " + e.getMessage();
        }
    }
}
