/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2025 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.picketlink.identity.federation.bindings.tomcat.sp;

import java.security.Principal;
import java.util.List;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.realm.GenericPrincipal;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;

/**
 * Common code useful for a SP
 *
 */
public class SPUtil {
    
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    
    /**
     * Create a SAML2 auth request
     *
     * @param serviceURL URL of the service
     * @param identityURL URL of the identity provider
     * @return
     * @throws ConfigurationException
     */
    public AuthnRequestType createSAMLRequest(String serviceURL, String identityURL) throws ConfigurationException {
        if (serviceURL == null)
            throw logger.nullArgumentError("serviceURL");
        if (identityURL == null)
            throw logger.nullArgumentError("identityURL");

        SAML2Request saml2Request = new SAML2Request();
        String id = IDGenerator.create("ID_");
        return saml2Request.createAuthnRequestType(id, serviceURL, identityURL, serviceURL);
    }

    /**
     * Create an instance of the {@link GenericPrincipal}
     * @param request
     * @param username
     * @param roles
     * @return
     */
    public Principal createGenericPrincipal(Request request, String username, List<String> roles) {
        Context ctx = request.getContext();
        return new GenericPrincipal(username, roles);
    }
}