package org.gatein.sso.saml.plugin.valve;

import org.apache.catalina.LifecycleException;

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