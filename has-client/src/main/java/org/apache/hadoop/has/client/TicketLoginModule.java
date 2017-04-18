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
package org.apache.hadoop.has.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import sun.misc.HexDumpEncoder;
import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Credentials;
import sun.security.krb5.EncryptionKey;
import sun.security.krb5.KrbAsReqBuilder;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.RefreshFailedException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.File;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

public class TicketLoginModule implements LoginModule {

      public static final Log LOG = LogFactory.getLog(TicketLoginModule.class);
    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, Object> sharedState;
    private Map<String, ?> options;

    // configurable option
    private boolean debug = false;
    private boolean storeKey = false;
    private boolean doNotPrompt = false;
    private boolean useTicketCache = false;
    private boolean useKeyTab = false;
    private boolean useTgtTicket = false;
    private String ticketCacheName = null;
    private String keyTabName = null;
    private String princName = null;

    private boolean useFirstPass = false;
    private boolean tryFirstPass = false;
    private boolean storePass = false;
    private boolean clearPass = false;
    private boolean refreshKrb5Config = false;
    private boolean renewTGT = false;

    // specify if initiator.
    // perform authentication exchange if initiator
    private boolean isInitiator = true;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;
    private String username;

    // Encryption keys calculated from password. Assigned when storekey == true
    // and useKeyTab == false (or true but not found)
    private EncryptionKey[] encKeys = null;

    KeyTab ktab = null;

    private Credentials cred = null;

    private PrincipalName principal = null;
    private KerberosPrincipal kerbClientPrinc = null;
    private KerberosTicket kerbTicket = null;
    private KerberosKey[] kerbKeys = null;
    private StringBuffer krb5PrincName = null;
    private boolean unboundServer = false;
    private char[] password = null;

    private static final String NAME = "javax.security.auth.login.name";
    private static final String PWD = "javax.security.auth.login.password";
    private static final ResourceBundle rb = AccessController.doPrivileged(
            new PrivilegedAction<ResourceBundle>() {
                public ResourceBundle run() {
                    return ResourceBundle.getBundle(
                            "sun.security.util.AuthResources");
                }
            }
    );

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * <p>
     * @param subject the <code>Subject</code> to be authenticated. <p>
     *
     * @param callbackHandler a <code>CallbackHandler</code> for
     *                  communication with the end user (prompting for
     *                  usernames and passwords, for example). <p>
     *
     * @param sharedState shared <code>LoginModule</code> state. <p>
     *
     * @param options options specified in the login
     *                  <code>Configuration</code> for this particular
     *                  <code>LoginModule</code>.
     */
    // Unchecked warning from (Map<String, Object>)sharedState is safe
    // since javax.security.auth.login.LoginContext passes a raw HashMap.
    // Unchecked warnings from options.get(String) are safe since we are
    // passing known keys.
    @SuppressWarnings("unchecked")
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = (Map<String, Object>)sharedState;
        this.options = options;

        // initialize any configured options

        debug = "true".equalsIgnoreCase((String)options.get("debug"));
        storeKey = "true".equalsIgnoreCase((String)options.get("storeKey"));
        doNotPrompt = "true".equalsIgnoreCase((String)options.get
                                              ("doNotPrompt"));
        useTicketCache = "true".equalsIgnoreCase((String)options.get
                                                 ("useTicketCache"));
        useKeyTab = "true".equalsIgnoreCase((String)options.get("useKeyTab"));
        useTgtTicket = "true".equalsIgnoreCase((String)options.get("useTgtTicket"));
        ticketCacheName = (String)options.get("ticketCache");
        keyTabName = (String)options.get("keyTab");
        if (keyTabName != null) {
            keyTabName = sun.security.krb5.internal.ktab.KeyTab.normalize(
                         keyTabName);
        }
        princName = (String)options.get("principal");
        refreshKrb5Config =
            "true".equalsIgnoreCase((String)options.get("refreshKrb5Config"));
        renewTGT =
            "true".equalsIgnoreCase((String)options.get("renewTGT"));

        // check isInitiator value
        String isInitiatorValue = ((String)options.get("isInitiator"));
        if (isInitiatorValue == null) {
            // use default, if value not set
        } else {
            isInitiator = "true".equalsIgnoreCase(isInitiatorValue);
        }

        tryFirstPass =
            "true".equalsIgnoreCase
            ((String)options.get("tryFirstPass"));
        useFirstPass =
            "true".equalsIgnoreCase
            ((String)options.get("useFirstPass"));
        storePass =
            "true".equalsIgnoreCase((String)options.get("storePass"));
        clearPass =
            "true".equalsIgnoreCase((String)options.get("clearPass"));
        if (debug) {
            System.out.print("Debug is  " + debug
                             + " storeKey " + storeKey
                             + " useTicketCache " + useTicketCache
                             + " useKeyTab " + useKeyTab
                             + " doNotPrompt " + doNotPrompt
                             + " ticketCache is " + ticketCacheName
                             + " isInitiator " + isInitiator
                             + " KeyTab is " + keyTabName
                             + " refreshKrb5Config is " + refreshKrb5Config
                             + " principal is " + princName
                             + " tryFirstPass is " + tryFirstPass
                             + " useFirstPass is " + useFirstPass
                             + " storePass is " + storePass
                             + " clearPass is " + clearPass + "\n");
        }
    }


    /**
     * Authenticate the user
     *
     * <p>
     *
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.
     *
     * @exception FailedLoginException if the authentication fails. <p>
     *
     * @exception LoginException if this <code>LoginModule</code>
     *          is unable to perform the authentication.
     */
    public boolean login() throws LoginException {

        if (refreshKrb5Config) {
            try {
                if (debug) {
                    System.out.println("Refreshing Kerberos configuration");
                }
                sun.security.krb5.Config.refresh();
            } catch (KrbException ke) {
                LoginException le = new LoginException(ke.getMessage());
                le.initCause(ke);
                throw le;
            }
        }
        String principalProperty = System.getProperty
            ("sun.security.krb5.principal");
        if (principalProperty != null) {
            krb5PrincName = new StringBuffer(principalProperty);
        } else {
            if (princName != null) {
                krb5PrincName = new StringBuffer(princName);
            }
        }

        validateConfiguration();

        if (krb5PrincName != null && krb5PrincName.toString().equals("*")) {
            unboundServer = true;
        }

        if (tryFirstPass) {
            try {
                attemptAuthentication(true);
                if (debug)
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "authentication succeeded");
                succeeded = true;
                cleanState();
                return true;
            } catch (LoginException le) {
                // authentication failed -- try again below by prompting
                cleanState();
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "tryFirstPass failed with:" +
                                       le.getMessage());
                }
            }
        } else if (useFirstPass) {
            try {
                attemptAuthentication(true);
                succeeded = true;
                cleanState();
                return true;
            } catch (LoginException e) {
                // authentication failed -- clean out state
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "authentication failed \n" +
                                       e.getMessage());
                }
                succeeded = false;
                cleanState();
                throw e;
            }
        }

        // attempt the authentication by getting the username and pwd
        // by prompting or configuration i.e. not from shared state

        try {
            attemptAuthentication(false);
            succeeded = true;
            cleanState();
            return true;
        } catch (LoginException e) {
            // authentication failed -- clean out state
            if (debug) {
                System.out.println("\t\t[Krb5LoginModule] " +
                                   "authentication failed \n" +
                                   e.getMessage());
            }
            succeeded = false;
            cleanState();
            throw e;
        }
    }
    /**
     * process the configuration options
     * Get the TGT either out of
     * cache or from the KDC using the password entered
     * Check the  permission before getting the TGT
     */

    private void attemptAuthentication(boolean getPasswdFromSharedState)
        throws LoginException {

        /*
         * Check the creds cache to see whether
         * we have TGT for this client principal
         */
        if (krb5PrincName != null) {
            try {
                principal = new PrincipalName
                    (krb5PrincName.toString(),
                     PrincipalName.KRB_NT_PRINCIPAL);
            } catch (KrbException e) {
                LoginException le = new LoginException(e.getMessage());
                le.initCause(e);
                throw le;
            }
        }

        try {

            if (useTgtTicket) {

                LOG.info("use tgt ticket##");

                if (debug)
                    System.out.println("Acquire TGT TICKET...");
                TgtTicket tgtTicket = null;
                try {
                    System.setProperty(HASClient.AK_ENV_NAME, "/home/ak.conf");
                    HASClient hasClient = new HASClient();
                    tgtTicket = hasClient.requestTgt();
                } catch (org.apache.kerby.kerberos.kerb.KrbException e) {
                    e.printStackTrace();
                }
                Credential credential = new Credential(tgtTicket);
                boolean[] flags = new boolean[7];
                int flag = credential.getTicketFlags().getFlags();
                for (int i = 6; i >= 0; i--) {
                    flags[i] = (flag & (1 << i)) != 0;
                }
                cred = new Credentials(credential.getTicket().encode(),
                    credential.getClientName().getName(),
                    credential.getServerName().getName(),
                    credential.getKey().getKeyData(),
                    credential.getKey().getKeyType().getValue(),
                    flags,
                    credential.getAuthTime().getValue(),
                    credential.getStartTime().getValue(),
                    credential.getEndTime().getValue(),
                    credential.getRenewTill().getValue(),
                    null);

                if (cred != null) {
                   // get the principal name from the ticket cache
                   if (principal == null) {
                        principal = cred.getClient();
                   }
                }
                if (debug) {
                    System.out.println("Principal is " + principal);
                    if (cred == null) {
                        System.out.println
                            ("null credentials from Ticket Cache");
                    }
                }
            } else if (useTicketCache) {
                LOG.info("use ticket cache!!!!!");
                // ticketCacheName == null implies the default cache
                if (debug)
                    System.out.println("Acquire TGT from Cache");
                cred  = Credentials.acquireTGTFromCache
                    (principal, ticketCacheName);

                if (cred != null) {
                    // check to renew credentials
                    if (!isCurrent(cred)) {
                        if (renewTGT) {
                            cred = renewCredentials(cred);
                        } else {
                            // credentials have expired
                            cred = null;
                            if (debug)
                                System.out.println("Credentials are" +
                                                " no longer valid");
                        }
                    }
                }

                if (cred != null) {
                   // get the principal name from the ticket cache
                   if (principal == null) {
                        principal = cred.getClient();
                   }
                }
                if (debug) {
                    System.out.println("Principal is " + principal);
                    if (cred == null) {
                        System.out.println
                            ("null credentials from Ticket Cache");
                    }
                }
            }

            // cred = null indicates that we didn't get the creds
            // from the cache or useTicketCache was false

            if (cred == null) {
                // We need the principal name whether we use keytab
                // or AS Exchange
                if (principal == null) {
                    promptForName(getPasswdFromSharedState);
                    principal = new PrincipalName
                        (krb5PrincName.toString(),
                         PrincipalName.KRB_NT_PRINCIPAL);
                }

                /*
                 * Before dynamic KeyTab support (6894072), here we check if
                 * the keytab contains keys for the principal. If no, keytab
                 * will not be used and password is prompted for.
                 *
                 * After 6894072, we normally don't check it, and expect the
                 * keys can be populated until a real connection is made. The
                 * check is still done when isInitiator == true, where the keys
                 * will be used right now.
                 *
                 * Probably tricky relations:
                 *
                 * useKeyTab is config flag, but when it's true but the ktab
                 * does not contains keys for principal, we would use password
                 * and keep the flag unchanged (for reuse?). In this method,
                 * we use (ktab != null) to check whether keytab is used.
                 * After this method (and when storeKey == true), we use
                 * (encKeys == null) to check.
                 */
                if (useKeyTab) {
                    LOG.info("use keytab");
                    if (!unboundServer) {
                        KerberosPrincipal kp =
                                new KerberosPrincipal(principal.getName());
                        ktab = (keyTabName == null)
                                ? KeyTab.getInstance(kp)
                                : KeyTab.getInstance(kp, new File(keyTabName));
                    } else {
                        ktab = (keyTabName == null)
                                ? KeyTab.getUnboundInstance()
                                : KeyTab.getUnboundInstance(new File(keyTabName));
                    }
                    if (isInitiator) {
                        if (Krb5Util.keysFromJavaxKeyTab(ktab, principal).length
                                == 0) {
                            ktab = null;
                            if (debug) {
                                System.out.println
                                    ("Key for the principal " +
                                     principal  +
                                     " not available in " +
                                     ((keyTabName == null) ?
                                      "default key tab" : keyTabName));
                            }
                        }
                    }
                }

                KrbAsReqBuilder builder;

                if (ktab == null) {
                    promptForPass(getPasswdFromSharedState);
                    builder = new KrbAsReqBuilder(principal, password);
                    if (isInitiator) {
                        // XXX Even if isInitiator=false, it might be
                        // better to do an AS-REQ so that keys can be
                        // updated with PA info
                        cred = builder.action().getCreds();
                    }
                    if (storeKey) {
                        encKeys = builder.getKeys(isInitiator);
                        // When encKeys is empty, the login actually fails.
                        // For compatibility, exception is thrown in commit().
                    }
                } else {
                    builder = new KrbAsReqBuilder(principal, ktab);
                    if (isInitiator) {
                        cred = builder.action().getCreds();
                    }
                }
                builder.destroy();

                if (debug) {
                    System.out.println("principal is " + principal);
                    HexDumpEncoder hd = new HexDumpEncoder();
                    if (ktab != null) {
                        System.out.println("Will use keytab");
                    } else if (storeKey) {
                        for (int i = 0; i < encKeys.length; i++) {
                            System.out.println("EncryptionKey: keyType=" +
                                encKeys[i].getEType() +
                                " keyBytes (hex dump)=" +
                                hd.encodeBuffer(encKeys[i].getBytes()));
                        }
                    }
                }

                // we should hava a non-null cred
                if (isInitiator && (cred == null)) {
                    throw new LoginException
                        ("TGT Can not be obtained from the KDC ");
                }

            }
        } catch (KrbException e) {
            LoginException le = new LoginException(e.getMessage());
            le.initCause(e);
            throw le;
        } catch (IOException ioe) {
            LoginException ie = new LoginException(ioe.getMessage());
            ie.initCause(ioe);
            throw ie;
        }
    }

    private void promptForName(boolean getPasswdFromSharedState)
        throws LoginException {
        krb5PrincName = new StringBuffer("");
        if (getPasswdFromSharedState) {
            // use the name saved by the first module in the stack
            username = (String)sharedState.get(NAME);
            if (debug) {
                System.out.println
                    ("username from shared state is " + username + "\n");
            }
            if (username == null) {
                System.out.println
                    ("username from shared state is null\n");
                throw new LoginException
                    ("Username can not be obtained from sharedstate ");
            }
            if (debug) {
                System.out.println
                    ("username from shared state is " + username + "\n");
            }
            if (username != null && username.length() > 0) {
                krb5PrincName.insert(0, username);
                return;
            }
        }

        if (doNotPrompt) {
            throw new LoginException
                ("Unable to obtain Principal Name for authentication ");
        } else {
            if (callbackHandler == null)
                throw new LoginException("No CallbackHandler "
                                         + "available "
                                         + "to garner authentication "
                                         + "information from the user");
            try {
                String defUsername = System.getProperty("user.name");

                Callback[] callbacks = new Callback[1];
                MessageFormat form = new MessageFormat(
                                       rb.getString(
                                       "Kerberos.username.defUsername."));
                Object[] source =  {defUsername};
                callbacks[0] = new NameCallback(form.format(source));
                callbackHandler.handle(callbacks);
                username = ((NameCallback)callbacks[0]).getName();
                if (username == null || username.length() == 0)
                    username = defUsername;
                krb5PrincName.insert(0, username);

            } catch (IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException
                    (uce.getMessage()
                     +" not available to garner "
                     +" authentication information "
                     +" from the user");
            }
        }
    }

    private void promptForPass(boolean getPasswdFromSharedState)
        throws LoginException {

        if (getPasswdFromSharedState) {
            // use the password saved by the first module in the stack
            password = (char[])sharedState.get(PWD);
            if (password == null) {
                if (debug) {
                    System.out.println
                        ("Password from shared state is null");
                }
                throw new LoginException
                    ("Password can not be obtained from sharedstate ");
            }
            if (debug) {
                System.out.println
                    ("password is " + new String(password));
            }
            return;
        }
        if (doNotPrompt) {
            throw new LoginException
                ("Unable to obtain password from user\n");
        } else {
            if (callbackHandler == null)
                throw new LoginException("No CallbackHandler "
                                         + "available "
                                         + "to garner authentication "
                                         + "information from the user");
            try {
                Callback[] callbacks = new Callback[1];
                String userName = krb5PrincName.toString();
                MessageFormat form = new MessageFormat(
                                         rb.getString(
                                         "Kerberos.password.for.username."));
                Object[] source = {userName};
                callbacks[0] = new PasswordCallback(
                                                    form.format(source),
                                                    false);
                callbackHandler.handle(callbacks);
                char[] tmpPassword = ((PasswordCallback)
                                      callbacks[0]).getPassword();
                if (tmpPassword == null) {
                    throw new LoginException("No password provided");
                }
                password = new char[tmpPassword.length];
                System.arraycopy(tmpPassword, 0,
                                 password, 0, tmpPassword.length);
                ((PasswordCallback)callbacks[0]).clearPassword();


                // clear tmpPassword
                for (int i = 0; i < tmpPassword.length; i++)
                    tmpPassword[i] = ' ';
                tmpPassword = null;
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "user entered username: " +
                                       krb5PrincName);
                    System.out.println();
                }
            } catch (IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException(uce.getMessage()
                                         +" not available to garner "
                                         +" authentication information "
                                         + "from the user");
            }
        }
    }

    private void validateConfiguration() throws LoginException {
        if (doNotPrompt && !useTicketCache && !useKeyTab
                && !tryFirstPass && !useFirstPass && !useTgtTicket)
            throw new LoginException
                ("Configuration Error"
                 + " - either doNotPrompt should be "
                 + " false or at least one of useTicketCache, "
                 + " useKeyTab, tryFirstPass and useFirstPass"
                 + " should be true");
        if (ticketCacheName != null && !useTicketCache)
            throw new LoginException
                ("Configuration Error "
                 + " - useTicketCache should be set "
                 + "to true to use the ticket cache"
                 + ticketCacheName);
        if (keyTabName != null & !useKeyTab)
            throw new LoginException
                ("Configuration Error - useKeyTab should be set to true "
                 + "to use the keytab" + keyTabName);
        if (storeKey && doNotPrompt && !useKeyTab
                && !tryFirstPass && !useFirstPass)
            throw new LoginException
                ("Configuration Error - either doNotPrompt should be set to "
                 + " false or at least one of tryFirstPass, useFirstPass "
                 + "or useKeyTab must be set to true for storeKey option");
        if (renewTGT && !useTicketCache)
            throw new LoginException
                ("Configuration Error"
                 + " - either useTicketCache should be "
                 + " true or renewTGT should be false");
        if (krb5PrincName != null && krb5PrincName.toString().equals("*")) {
            if (isInitiator) {
                throw new LoginException
                    ("Configuration Error"
                    + " - principal cannot be * when isInitiator is true");
            }
        }
    }

    private boolean isCurrent(Credentials creds)
    {
        Date endTime = creds.getEndTime();
        if (endTime != null) {
            return (System.currentTimeMillis() <= endTime.getTime());
        }
        return true;
    }

    private Credentials renewCredentials(Credentials creds)
    {
        Credentials lcreds;
        try {
            if (!creds.isRenewable())
                throw new RefreshFailedException("This ticket" +
                                " is not renewable");
            if (System.currentTimeMillis() > cred.getRenewTill().getTime())
                throw new RefreshFailedException("This ticket is past "
                                             + "its last renewal time.");
            lcreds = creds.renew();
            if (debug)
                System.out.println("Renewed Kerberos Ticket");
        } catch (Exception e) {
            lcreds = null;
            if (debug)
                System.out.println("Ticket could not be renewed : "
                                + e.getMessage());
        }
        return lcreds;
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules succeeded).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method associates a
     * <code>Krb5Principal</code>
     * with the <code>Subject</code> located in the
     * <code>LoginModule</code>. It adds Kerberos Credentials to the
     *  the Subject's private credentials set. If this LoginModule's own
     * authentication attempted failed, then this method removes
     * any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the commit fails.
     *
     * @return true if this LoginModule's own login and commit
     *          attempts succeeded, or false otherwise.
     */

    public boolean commit() throws LoginException {

        /*
         * Let us add the Krb5 Creds to the Subject's
         * private credentials. The credentials are of type
         * KerberosKey or KerberosTicket
         */

              StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
                for(StackTraceElement element : stackTraceElements) {
                    LOG.info("###!!stackTrace: " + element);
                }
        LOG.info("success"+succeeded);

        if (succeeded == false) {
            return false;
        } else {

            if (isInitiator && (cred == null)) {
                succeeded = false;
                throw new LoginException("Null Client Credential");
            }

            if (subject.isReadOnly()) {
                cleanKerberosCred();
                throw new LoginException("Subject is Readonly");
            }

            /*
             * Add the Principal (authenticated identity)
             * to the Subject's principal set and
             * add the credentials (TGT or Service key) to the
             * Subject's private credentials
             */

            Set<Object> privCredSet =  subject.getPrivateCredentials();
            Set<java.security.Principal> princSet  = subject.getPrincipals();
            kerbClientPrinc = new KerberosPrincipal(principal.getName());

            // create Kerberos Ticket
            if (isInitiator) {
                kerbTicket = Krb5Util.credsToTicket(cred);
            }

            if (storeKey && encKeys != null) {
                if (encKeys.length == 0) {
                    succeeded = false;
                    throw new LoginException("Null Server Key ");
                }

                kerbKeys = new KerberosKey[encKeys.length];
                for (int i = 0; i < encKeys.length; i ++) {
                    Integer temp = encKeys[i].getKeyVersionNumber();
                    kerbKeys[i] = new KerberosKey(kerbClientPrinc,
                                          encKeys[i].getBytes(),
                                          encKeys[i].getEType(),
                                          (temp == null?
                                          0: temp.intValue()));
                }

            }
            // Let us add the kerbClientPrinc,kerbTicket and KeyTab/KerbKey (if
            // storeKey is true)

            // We won't add "*" as a KerberosPrincipal
            if (!unboundServer &&
                    !princSet.contains(kerbClientPrinc)) {
                princSet.add(kerbClientPrinc);
            }

            // add the TGT
            if (kerbTicket != null) {
                if (!privCredSet.contains(kerbTicket))
                    privCredSet.add(kerbTicket);
            }

            if (storeKey) {
                if (encKeys == null) {
                    if (ktab != null) {
                        if (!privCredSet.contains(ktab)) {
                            privCredSet.add(ktab);
                        }
                    } else {
                        succeeded = false;
                        throw new LoginException("No key to store");
                    }
                } else {
                    for (int i = 0; i < kerbKeys.length; i ++) {
                        if (!privCredSet.contains(kerbKeys[i])) {
                            privCredSet.add(kerbKeys[i]);
                        }
                        encKeys[i].destroy();
                        encKeys[i] = null;
                        if (debug) {
                            System.out.println("Added server's key"
                                            + kerbKeys[i]);
                            System.out.println("\t\t[Krb5LoginModule] " +
                                           "added Krb5Principal  " +
                                           kerbClientPrinc.toString()
                                           + " to Subject");
                        }
                    }
                }
            }
        }
        commitSucceeded = true;
        if (debug)
            System.out.println("Commit Succeeded \n");
        return true;
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules did not succeed).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> and <code>commit</code> methods),
     * then this method cleans up any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the abort fails.
     *
     * @return false if this LoginModule's own login and/or commit attempts
     *          failed, and true otherwise.
     */

    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
            cleanKerberosCred();
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * Logout the user.
     *
     * <p> This method removes the <code>Krb5Principal</code>
     * that was added by the <code>commit</code> method.
     *
     * <p>
     *
     * @exception LoginException if the logout fails.
     *
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.
     */
    public boolean logout() throws LoginException {

        if (debug) {
            System.out.println("\t\t[Krb5LoginModule]: " +
                "Entering logout");
        }

        if (subject.isReadOnly()) {
            cleanKerberosCred();
            throw new LoginException("Subject is Readonly");
        }

        subject.getPrincipals().remove(kerbClientPrinc);
           // Let us remove all Kerberos credentials stored in the Subject
        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof KerberosTicket ||
                    o instanceof KerberosKey ||
                    o instanceof KeyTab) {
                it.remove();
            }
        }
        // clean the kerberos ticket and keys
        cleanKerberosCred();

        succeeded = false;
        commitSucceeded = false;
        if (debug) {
            System.out.println("\t\t[Krb5LoginModule]: " +
                               "logged out Subject");
        }
        return true;
    }

    /**
     * Clean Kerberos credentials
     */
    private void cleanKerberosCred() throws LoginException {
        // Clean the ticket and server key
        try {
            if (kerbTicket != null)
                kerbTicket.destroy();
            if (kerbKeys != null) {
                for (int i = 0; i < kerbKeys.length; i++) {
                    kerbKeys[i].destroy();
                }
            }
        } catch (DestroyFailedException e) {
            throw new LoginException
                ("Destroy Failed on Kerberos Private Credentials");
        }
        kerbTicket = null;
        kerbKeys = null;
        kerbClientPrinc = null;
    }

    /**
     * Clean out the state
     */
    private void cleanState() {

        // save input as shared state only if
        // authentication succeeded
        if (succeeded) {
            if (storePass &&
                !sharedState.containsKey(NAME) &&
                !sharedState.containsKey(PWD)) {
                sharedState.put(NAME, username);
                sharedState.put(PWD, password);
            }
        } else {
            // remove temp results for the next try
            encKeys = null;
            ktab = null;
            principal = null;
        }
        username = null;
        password = null;
        if (krb5PrincName != null && krb5PrincName.length() != 0)
            krb5PrincName.delete(0, krb5PrincName.length());
        krb5PrincName = null;
        if (clearPass) {
            sharedState.remove(NAME);
            sharedState.remove(PWD);
        }
    }
}
