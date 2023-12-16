package org.gatein.sso.saml.plugin.filter;

import java.util.Enumeration;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * This class is used to combine two HTTP Request datas
 */
public class SAMLHTTPRequestWrapper extends HttpServletRequestWrapper {
  private final HttpServletRequest originalHttpServletRequest;

  public SAMLHTTPRequestWrapper(HttpServletRequest request, HttpServletRequest originalHttpServletRequest) {
    super(request);
    this.originalHttpServletRequest = originalHttpServletRequest;
  }

  @Override
  public String getParameter(String name) {
    return originalHttpServletRequest.getParameter(name);
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    return originalHttpServletRequest.getParameterMap();
  }

  @Override
  public String[] getParameterValues(String name) {
    return originalHttpServletRequest.getParameterValues(name);
  }

  @Override
  public String getMethod() {
    return originalHttpServletRequest.getMethod();
  }

  @Override
  public String getHeader(String name) {
    return originalHttpServletRequest.getHeader(name);
  }

  @Override
  public Enumeration<String> getHeaders(String name) {
    return originalHttpServletRequest.getHeaders(name);
  }

  @Override
  public Enumeration<String> getHeaderNames() {
    return originalHttpServletRequest.getHeaderNames();
  }
}
