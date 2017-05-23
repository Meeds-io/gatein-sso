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