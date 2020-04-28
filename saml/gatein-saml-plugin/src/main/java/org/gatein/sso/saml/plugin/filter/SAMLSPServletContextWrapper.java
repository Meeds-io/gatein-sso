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
package org.gatein.sso.saml.plugin.filter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.EventListener;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.FilterRegistration.Dynamic;
import javax.servlet.RequestDispatcher;
import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import javax.servlet.descriptor.JspConfigDescriptor;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

/**
 * This class wraps an HTTP ServletContext to be able to get
 * a configuration file from local folder outside the webapp
 */
public class SAMLSPServletContextWrapper implements ServletContext {
  public static final String FILE_PREFIX = "file:";

  public static final Logger log         = LoggerFactory.getLogger(PortalIDPWebBrowserSSOFilter.class);

  private ServletContext     delegate;

  public SAMLSPServletContextWrapper(ServletContext delegate) {
    this.delegate = delegate;
  }

  @Override
  public Dynamic addFilter(String arg0, String arg1) {
    return delegate.addFilter(arg0, arg1);
  }

  @Override
  public Dynamic addFilter(String arg0, Filter arg1) {
    return delegate.addFilter(arg0, arg1);
  }

  @Override
  public Dynamic addFilter(String arg0, Class<? extends Filter> arg1) {
    return delegate.addFilter(arg0, arg1);
  }

  @Override
  public void addListener(String arg0) {
    delegate.addListener(arg0);
  }

  @Override
  public <T extends EventListener> void addListener(T arg0) {
    delegate.addListener(arg0);
  }

  @Override
  public void addListener(Class<? extends EventListener> arg0) {
    delegate.addListener(arg0);
  }

  @Override
  public javax.servlet.ServletRegistration.Dynamic addServlet(String arg0, String arg1) {
    return delegate.addServlet(arg0, arg1);
  }

  @Override
  public javax.servlet.ServletRegistration.Dynamic addServlet(String arg0, Servlet arg1) {
    return delegate.addServlet(arg0, arg1);
  }

  @Override
  public javax.servlet.ServletRegistration.Dynamic addServlet(String arg0, Class<? extends Servlet> arg1) {
    return delegate.addServlet(arg0, arg1);
  }

  @Override
  public <T extends Filter> T createFilter(Class<T> arg0) throws ServletException {
    return delegate.createFilter(arg0);
  }

  @Override
  public <T extends EventListener> T createListener(Class<T> arg0) throws ServletException {
    return delegate.createListener(arg0);
  }

  @Override
  public <T extends Servlet> T createServlet(Class<T> arg0) throws ServletException {
    return delegate.createServlet(arg0);
  }

  @Override
  public void declareRoles(String... arg0) {
    delegate.declareRoles(arg0);
  }

  @Override
  public Object getAttribute(String arg0) {
    return delegate.getAttribute(arg0);
  }

  @Override
  public Enumeration<String> getAttributeNames() {
    return delegate.getAttributeNames();
  }

  @Override
  public ClassLoader getClassLoader() {
    return delegate.getClassLoader();
  }

  @Override
  public ServletContext getContext(String arg0) {
    return delegate.getContext(arg0);
  }

  @Override
  public String getContextPath() {
    return delegate.getContextPath();
  }

  @Override
  public Set<SessionTrackingMode> getDefaultSessionTrackingModes() {
    return delegate.getDefaultSessionTrackingModes();
  }

  @Override
  public int getEffectiveMajorVersion() {
    return delegate.getEffectiveMajorVersion();
  }

  @Override
  public int getEffectiveMinorVersion() {
    return delegate.getEffectiveMinorVersion();
  }

  @Override
  public Set<SessionTrackingMode> getEffectiveSessionTrackingModes() {
    return delegate.getEffectiveSessionTrackingModes();
  }

  @Override
  public FilterRegistration getFilterRegistration(String arg0) {
    return delegate.getFilterRegistration(arg0);
  }

  @Override
  public Map<String, ? extends FilterRegistration> getFilterRegistrations() {
    return delegate.getFilterRegistrations();
  }

  @Override
  public String getInitParameter(String arg0) {
    return delegate.getInitParameter(arg0);
  }

  @Override
  public Enumeration<String> getInitParameterNames() {
    return delegate.getInitParameterNames();
  }

  @Override
  public JspConfigDescriptor getJspConfigDescriptor() {
    return delegate.getJspConfigDescriptor();
  }

  @Override
  public int getMajorVersion() {
    return delegate.getMajorVersion();
  }

  @Override
  public String getMimeType(String arg0) {
    return delegate.getMimeType(arg0);
  }

  @Override
  public int getMinorVersion() {
    return delegate.getMinorVersion();
  }

  @Override
  public RequestDispatcher getNamedDispatcher(String arg0) {
    return delegate.getNamedDispatcher(arg0);
  }

  @Override
  public String getRealPath(String arg0) {
    return delegate.getRealPath(arg0);
  }

  @Override
  public RequestDispatcher getRequestDispatcher(String arg0) {
    return delegate.getRequestDispatcher(arg0);
  }

  @Override
  public URL getResource(String arg0) throws MalformedURLException {
    if (isFSResolvable(arg0)) {
      return getFSResource(arg0);
    }
    return delegate.getResource(arg0);
  }

  @Override
  public InputStream getResourceAsStream(String arg0) {
    if (isFSResolvable(arg0)) {
      try {
        URL fsResource = getFSResource(arg0);
        if (fsResource != null) {
          return fsResource.openStream();
        }
      } catch (IOException e) {
        log.warn("Error occurred when retieving file" + arg0, e);
      }
    }
    return delegate.getResourceAsStream(arg0);
  }

  @Override
  public Set<String> getResourcePaths(String arg0) {
    return delegate.getResourcePaths(arg0);
  }

  @Override
  public String getServerInfo() {
    return delegate.getServerInfo();
  }

  @SuppressWarnings("deprecation")
  @Override
  public Servlet getServlet(String arg0) throws ServletException {
    return delegate.getServlet(arg0);
  }

  @Override
  public String getServletContextName() {
    return delegate.getServletContextName();
  }

  @SuppressWarnings("deprecation")
  @Override
  public Enumeration<String> getServletNames() {
    return delegate.getServletNames();
  }

  @Override
  public ServletRegistration getServletRegistration(String arg0) {
    return delegate.getServletRegistration(arg0);
  }

  @Override
  public Map<String, ? extends ServletRegistration> getServletRegistrations() {
    return delegate.getServletRegistrations();
  }

  @SuppressWarnings("deprecation")
  @Override
  public Enumeration<Servlet> getServlets() {
    return delegate.getServlets();
  }

  @Override
  public SessionCookieConfig getSessionCookieConfig() {
    return delegate.getSessionCookieConfig();
  }

  @Override
  public void log(String arg0) {
    delegate.log(arg0);
  }

  @SuppressWarnings("deprecation")
  @Override
  public void log(Exception arg0, String arg1) {
    delegate.log(arg0, arg1);
  }

  @Override
  public void log(String arg0, Throwable arg1) {
    delegate.log(arg0, arg1);
  }

  @Override
  public void removeAttribute(String arg0) {
    delegate.removeAttribute(arg0);
  }

  @Override
  public void setAttribute(String arg0, Object arg1) {
    delegate.setAttribute(arg0, arg1);
  }

  @Override
  public boolean setInitParameter(String arg0, String arg1) {
    return delegate.setInitParameter(arg0, arg1);
  }

  @Override
  public void setSessionTrackingModes(Set<SessionTrackingMode> arg0) {
    delegate.setSessionTrackingModes(arg0);
  }

  @SuppressWarnings("deprecation")
  public URL getFSResource(String url) throws MalformedURLException {
    String path = removeScheme(url);
    File file = new File(path);
    if (file.exists() && file.isFile())
      return file.toURL();
    return null;
  }

  protected String removeScheme(String url) {
    String scheme = FILE_PREFIX;
    if (url.startsWith(scheme)) {
      return url.substring(scheme.length());
    }
    return url;
  }

  public boolean isFSResolvable(String url) {
    return url.startsWith(FILE_PREFIX);
  }

  @Override
  public String getVirtualServerName() {
    return delegate.getVirtualServerName();
  }
}
