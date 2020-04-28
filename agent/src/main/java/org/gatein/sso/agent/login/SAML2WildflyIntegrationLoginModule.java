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
package org.gatein.sso.agent.login;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.picketlink.identity.federation.bindings.wildfly.SAML2LoginModule;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;

public class SAML2WildflyIntegrationLoginModule extends SAML2LoginModule {
  // Name of security-domain (actually not used by this impl)
  private static final String   OPTION_REALM_NAME            = "realmName";

  // Name of portalContainer
  private static final String   OPTION_PORTAL_CONTAINER_NAME = "portalContainerName";

  // If this boolean property is true, then final principal will use roles from
  // SAML.
  // If false, then we don't use roles from SAML, but we will delegate filling
  // of "Roles" principal to next login module in stack
  // (actually it is JbossLoginModule, which uses JAAS roles from GateIn
  // database)
  // Default value is false, so we are preferring delegation to JbossLoginModule
  // and using roles from portal DB.
  private static final String   OPTION_USE_SAML_ROLES        = "useSAMLRoles";

  private static final String[] ALL_VALID_OPTIONS            =
                                                  { OPTION_PORTAL_CONTAINER_NAME, OPTION_REALM_NAME, OPTION_USE_SAML_ROLES };

  private String                portalContainerName;

  private boolean               useSAMLRoles;

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
    try {
      addValidOptions(ALL_VALID_OPTIONS);
    } catch (NoSuchMethodError ignore) {
      // Method addValidOptions is new in picketbox. Not supported on older AS
      // 7.1.1
    }

    super.initialize(subject, callbackHandler, sharedState, options);

    // GateIn integration
    this.portalContainerName = getPortalContainerName(options);

    String useSAMLRoles = (String) options.get(OPTION_USE_SAML_ROLES);
    this.useSAMLRoles = useSAMLRoles != null && "true".equals(useSAMLRoles);

    if (log.isTraceEnabled()) {
      log.trace("Using options: " + OPTION_PORTAL_CONTAINER_NAME + "=" + this.portalContainerName + ", " + OPTION_USE_SAML_ROLES
          + "=" + this.useSAMLRoles);
    }
  }

  @Override
  public boolean login() throws javax.security.auth.login.LoginException {
    if (super.login()) {
      // Username is already in sharedState thanks to superclass
      String username = getUsernameFromSharedState();
      if (log.isTraceEnabled()) {
        log.trace("Found user " + username + " in shared state.");
      }

      try {
        // Perform authentication by setting up the proper Application State
        Authenticator authenticator = (Authenticator) getContainer().getComponentInstanceOfType(Authenticator.class);

        Identity identity = authenticator.createIdentity(username);
        sharedState.put("exo.security.identity", identity);
        subject.getPublicCredentials().add(new UsernameCredential(username));

        return true;
      } catch (Exception e) {
        log.debug("Exception during login process: " + e.getMessage(), e);
        throw new LoginException(e.getMessage());
      }
    } else {
      return false;
    }
  }

  protected String getUsernameFromSharedState() {
    Object tmp = sharedState.get("javax.security.auth.login.name");
    if (tmp == null) {
      return null;
    } else if (tmp instanceof Principal) {
      return ((Principal) tmp).getName();
    } else {
      return (String) tmp;
    }
  }

  @Override
  protected Group[] getRoleSets() throws LoginException {
    if (useSAMLRoles) {
      return super.getRoleSets();
    } else {
      // Delegate creation of Group principal to next login module
      return new Group[] {};
    }
  }

  private String getPortalContainerName(Map options) {
    if (options != null) {
      String optionValue = (String) options.get(OPTION_PORTAL_CONTAINER_NAME);
      if (optionValue != null && optionValue.length() > 0) {
        return optionValue;
      }
    }
    return PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME;
  }

  private ExoContainer getContainer() throws Exception {
    ExoContainer container = ExoContainerContext.getCurrentContainer();
    if (container instanceof RootContainer) {
      container = RootContainer.getInstance().getPortalContainer(portalContainerName);
    }
    return container;
  }

}
