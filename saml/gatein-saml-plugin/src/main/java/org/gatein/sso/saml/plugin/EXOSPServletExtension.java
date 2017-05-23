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
