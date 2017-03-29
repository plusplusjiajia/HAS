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
package org.apache.hadoop.has.kdc;


import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.request.AsRequest;
import org.apache.kerby.kerberos.kerb.server.request.TgtTicketIssuer;
import org.apache.kerby.kerberos.kerb.server.request.TicketIssuer;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.kdc.AsRep;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.EncKdcRepPart;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcRep;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenRequest extends AsRequest{
    private static final Logger LOG = LoggerFactory.getLogger(TokenRequest.class);

    private Ticket ticket;
    private KdcRep reply;

    public TokenRequest(AsReq asReq, KdcContext kdcContext) {
        super(asReq, kdcContext);
    }

    /**
     * Process the kdcrequest from client and issue the ticket.
     *
     * @throws org.apache.kerby.kerberos.kerb.KrbException e.
     */
    public void process() throws KrbException {

        issueTicket();
        makeReply();
    }

    protected void issueTicket() throws KrbException {
        TicketIssuer issuer = new TgtTicketIssuer(this);
        Ticket newTicket = issuer.issueTicket();
        LOG.info("AS_REQ ISSUE: authtime " + newTicket.getEncPart().getAuthTime().getTime() + ","
            + newTicket.getEncPart().getCname() + " for "
            + newTicket.getSname());
        setTicket(newTicket);
    }

    protected void makeReply() throws KrbException {

        Ticket ticket = getTicket();

        AsRep reply = new AsRep();
        reply.setTicket(ticket);

        reply.setCname(getClientEntry().getPrincipal());
        reply.setCrealm(getKdcContext().getKdcRealm());

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey clientKey = getClientKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
            clientKey, KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);

        if (isPkinit()) {
            reply.setPaData(getPreauthContext().getOutputPaData());
        }

        setReply(reply);
    }

        /**
     * Get the reply message.
     *
     * @return reply
     */
    public KrbMessage getReply() {
        return reply;
    }

    /**
     * Set kdc reply.
     *
     * @param reply reply
     */
    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

        /**
     * Get ticket.
     *
     * @return ticket
     */
    public Ticket getTicket() {
        return ticket;
    }

    /**
     * Set ticket.
     *
     * @param ticket ticket
     */
    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

}
