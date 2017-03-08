/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.hadoop.haskdc;

import org.apache.kerby.kerberos.kdc.impl.NettyKdcServerImpl;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.util.OSUtil;

import java.io.File;

/**
 * The HAS KDC server implementation.
 */
public class HASKdcServer extends KdcServer {
    public HASKdcServer(File confDir) throws KrbException {
        super(confDir);
        setInnerKdcImpl(new NettyKdcServerImpl(getKdcSetting()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init() throws KrbException {
        super.init();

        LocalKadmin kadmin = new LocalKadminImpl(getKdcSetting(), getIdentityService());

        kadmin.checkBuiltinPrincipals();
    }

    private static final String USAGE = (OSUtil.isWindows()
            ? "Usage: bin\\start-kdc.cmd" : "Usage: sh bin/start-kdc.sh")
            + " <conf-dir> <working-dir> \n"
            + "\tExample:\n"
            + "\t\t"
            + (OSUtil.isWindows()
            ? "bin\\start-kdc.cmd" : "sh bin/start-kdc.sh")
            + " conf runtime\n";

    public static void main(String[] args) throws KrbException {
        if (args.length != 3) {
            System.err.println(USAGE);
            System.exit(1);
        }

        if (!args[0].equals("-start")) {
            System.err.println(USAGE);
            System.exit(2);
        }

        String confDirPath = args[1];
        String workDirPath = args[2];
        File confDir = new File(confDirPath);
        File workDir = new File(workDirPath);
        if (!confDir.exists() || !workDir.exists()) {
            System.err.println("Invalid or not exist conf-dir or work-dir");
            System.exit(3);
        }

        HASKdcServer server = new HASKdcServer(confDir);
        server.setWorkDir(workDir);
        try {
            server.init();
        } catch (KrbException e) {
            System.err.println("Errors occurred when start kdc server:  " + e.getMessage());
            System.exit(4);
        }

        server.start();
        System.out.println("HAS KDC server started.");
    }
}