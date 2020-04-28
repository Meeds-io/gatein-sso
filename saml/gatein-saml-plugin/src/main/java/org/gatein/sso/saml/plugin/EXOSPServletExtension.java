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
package org.gatein.sso.saml.plugin;

import javax.servlet.ServletContext;

import org.apache.commons.lang.StringUtils;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.bindings.wildfly.sp.SPServletExtension;

import org.exoplatform.container.RootContainer;
import org.exoplatform.container.definition.PortalContainerConfig;

import io.undertow.servlet.api.DeploymentInfo;

public class EXOSPServletExtension extends SPServletExtension {
  private PortalContainerConfig containerConfig = null;

  public EXOSPServletExtension() {
    if (isPortalContainerActivated() && containerConfig == null) {
      containerConfig = RootContainer.getInstance().getComponentInstanceOfType(PortalContainerConfig.class);
    }
  }

  @Override
  public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
    if(!isPortalContainerActivated()) {
      // This extension shouldn't be deployed
      // Extension not deployed for SAML with SP REST callback
      return;
    } else {
      String contextName = servletContext.getContextPath().startsWith("/") ? servletContext.getContextPath().substring(1)
                                                                           : servletContext.getContextPath();
      // Deploy this extension only for PortalContainer Contexts (portal by default)
      if (containerConfig.isPortalContainerName(contextName) && !containerConfig.isPortalContainerNameDisabled(contextName)) {
        String property = System.getProperty("gatein.sso.saml.sp.enabled");
        if (StringUtils.isNotBlank(property) && "true".equalsIgnoreCase(property.trim())) {
          String samlConfigFile = System.getProperty("gatein.sso.saml.config.file");
          // Use Specific SAML config file
          servletContext.setInitParameter(GeneralConstants.CONFIG_FILE, samlConfigFile);
          super.handleDeployment(deploymentInfo, servletContext);
        }
      }
    }
  }
  
  private boolean isPortalContainerActivated() {
    try {
      Class.forName("org.exoplatform.container.RootContainer");
      return true;
    } catch (ClassNotFoundException e) {
      return false;
    }
  }
}
