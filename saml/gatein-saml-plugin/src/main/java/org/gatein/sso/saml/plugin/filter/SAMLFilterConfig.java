package org.gatein.sso.saml.plugin.filter;

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

import org.gatein.sso.agent.filter.api.SSOInterceptorInitializationContext;

/**
 * This HTTP FilterConfig allows to inject some eXo Kernel Init Params
 * to Servlet Context Init Params
 */
public class SAMLFilterConfig implements FilterConfig {
  private String                              filterName;

  private ServletContext                      servletContext;

  private SSOInterceptorInitializationContext interceptorContext;

  public SAMLFilterConfig(String filterName,
                          ServletContext servletContext,
                          SSOInterceptorInitializationContext interceptorContext) {
    this.filterName = filterName;
    this.servletContext = servletContext;
    this.interceptorContext = interceptorContext;
  }

  @Override
  public ServletContext getServletContext() {
    return servletContext;
  }

  @Override
  public Enumeration<String> getInitParameterNames() {
    return null;
  }

  @Override
  public String getInitParameter(String name) {
    return interceptorContext.getInitParameter(name);
  }

  @Override
  public String getFilterName() {
    return filterName;
  }
}
