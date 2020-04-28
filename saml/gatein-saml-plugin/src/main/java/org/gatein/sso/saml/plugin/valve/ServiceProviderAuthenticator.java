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

import org.apache.catalina.LifecycleException;


/**
 * Unified Service Provider Authenticator
 * Forked from org.picketlink.identity.federation.bindings.tomcat.sp.ServiceProviderAuthenticator
 * and made compatible with Tomcat 8.5 since picketlink doesn't provide such a support
 */
public class ServiceProviderAuthenticator extends AbstractSPFormAuthenticator {

    @Override
    protected synchronized void startInternal() throws LifecycleException {
      super.startInternal();
      startPicketLink(); 
    }
    
    @Override
    protected String getContextPath() { 
        return getContext().getServletContext().getContextPath();
    }
}