/*
 * This file is part of the Meeds project (https://meeds.io/).
 * Copyright (C) 2020 Meeds Association
 * contact@meeds.io
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.gatein.sso.saml.plugin.valve;

import static org.picketlink.common.util.StringUtil.isNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.tomcat.sp.SPUtil;
import org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AssertionType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AuthenticationStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11StatementAbstractType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11ResponseType;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.federation.web.util.ServerDetector;

/**
 * Authenticator for SAML 1.1 processing at the Service Provider
 * forked from org.picketlink.identity.federation.bindings.tomcat.sp.AbstractSAML11SPRedirectFormAuthenticator
 * and made compatible with Tomcat 8.5 since picketlink doesn't provide such a support
 */
public abstract class AbstractSAML11SPRedirectFormAuthenticator extends AbstractSPFormAuthenticator {

    @Override
    public boolean authenticate(Request request, HttpServletResponse response) throws IOException {
      LoginConfig loginConfig = request.getContext().getLoginConfig();
      return authenticate(request, response, loginConfig);
    }

    public boolean authenticate(Request request, HttpServletResponse response, LoginConfig loginConfig) throws IOException {
        if (handleSAML11UnsolicitedResponse(request, response, loginConfig, this)) {
            return true;
        }

        logger.trace("Falling back on local Form Authentication if available");
        // fallback
        return super.authenticate(request, response);
    }

    public static boolean handleSAML11UnsolicitedResponse(Request request, HttpServletResponse response, LoginConfig loginConfig, AbstractSPFormAuthenticator formAuthenticator) throws IOException {
        String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

        Principal principal = request.getUserPrincipal();

        // If we have already authenticated the user and there is no request from IDP or logout from user
        if (principal != null)
            return true;

        Session session = request.getSessionInternal(true);

        // See if we got a response from IDP
        if (isNotNull(samlResponse)) {
            boolean isValid = false;
            try {
                isValid = formAuthenticator.validate(request);
            } catch (Exception e) {
                logger.samlSPHandleRequestError(e);
                throw new IOException();
            }
            if (!isValid)
                throw new IOException(ErrorCodes.VALIDATION_CHECK_FAILED);

            try {
                InputStream base64DecodedResponse = RedirectBindingUtil.base64DeflateDecode(samlResponse);
                SAMLParser parser = new SAMLParser();
                SAML11ResponseType saml11Response = (SAML11ResponseType) parser.parse(base64DecodedResponse);

                List<SAML11AssertionType> assertions = saml11Response.get();
                if (assertions.size() > 1) {
                    logger.trace("More than one assertion from IDP. Considering the first one.");
                }
                String username = null;
                List<String> roles = new ArrayList<String>();
                SAML11AssertionType assertion = assertions.get(0);
                if (assertion != null) {
                    // Get the subject
                    List<SAML11StatementAbstractType> statements = assertion.getStatements();
                    for (SAML11StatementAbstractType statement : statements) {
                        if (statement instanceof SAML11AuthenticationStatementType) {
                            SAML11AuthenticationStatementType subStat = (SAML11AuthenticationStatementType) statement;
                            SAML11SubjectType subject = subStat.getSubject();
                            username = subject.getChoice().getNameID().getValue();
                        }
                    }
                    roles = AssertionUtil.getRoles(assertion, null);
                }

                String password = ServiceProviderSAMLContext.EMPTY_PASSWORD;

                // Map to JBoss specific principal
                if ((new ServerDetector()).isJboss() || formAuthenticator.jbossEnv) {
                    // Push a context
                    ServiceProviderSAMLContext.push(username, roles);
                    principal = formAuthenticator.getContext().getRealm().authenticate(username, password);
                    ServiceProviderSAMLContext.clear();
                } else {
                    // tomcat env
                    SPUtil spUtil = new SPUtil();
                    principal = spUtil.createGenericPrincipal(request, username, roles);
                }

                session.setNote(Constants.SESS_USERNAME_NOTE, username);
                session.setNote(Constants.SESS_PASSWORD_NOTE, password);
                request.setUserPrincipal(principal);

                if (formAuthenticator.saveRestoreRequest) {
                    formAuthenticator.restoreRequest(request, session);
                }
                formAuthenticator.register(request, response, principal, HttpServletRequest.FORM_AUTH, username, password);

                return true;
            } catch (Exception e) {
                logger.samlSPHandleRequestError(e);
            }
        }

        return false;
    }

    protected void startPicketLink() throws LifecycleException{
        super.startPicketLink();
        this.spConfiguration.setBindingType("REDIRECT");
    }
}