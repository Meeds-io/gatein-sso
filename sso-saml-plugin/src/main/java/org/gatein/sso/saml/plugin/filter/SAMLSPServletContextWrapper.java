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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.FilterRegistration.Dynamic;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.SessionTrackingMode;
import jakarta.servlet.descriptor.JspConfigDescriptor;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

/**
 * This class wraps an HTTP ServletContext to be able to get a configuration
 * file from local folder outside the webapp
 */
public class SAMLSPServletContextWrapper implements ServletContext {
  public static final String FILE_PREFIX = "file:";

  private static final Log   LOG         = ExoLogger.getLogger(SAMLSPServletContextWrapper.class);

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
  public jakarta.servlet.ServletRegistration.Dynamic addServlet(String arg0, String arg1) {
    return delegate.addServlet(arg0, arg1);
  }

  @Override
  public jakarta.servlet.ServletRegistration.Dynamic addServlet(String arg0, Servlet arg1) {
    return delegate.addServlet(arg0, arg1);
  }

  @Override
  public jakarta.servlet.ServletRegistration.Dynamic addServlet(String arg0, Class<? extends Servlet> arg1) {
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
        LOG.warn("Error occurred when retieving file" + arg0, e);
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

  @Override
  public String getServletContextName() {
    return delegate.getServletContextName();
  }

  @Override
  public ServletRegistration getServletRegistration(String arg0) {
    return delegate.getServletRegistration(arg0);
  }

  @Override
  public Map<String, ? extends ServletRegistration> getServletRegistrations() {
    return delegate.getServletRegistrations();
  }

  @Override
  public SessionCookieConfig getSessionCookieConfig() {
    return delegate.getSessionCookieConfig();
  }

  @Override
  public void log(String arg0) {
    delegate.log(arg0);
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

  @Override
  public jakarta.servlet.ServletRegistration.Dynamic addJspFile(String servletName, String jspFile) {
    return delegate.addJspFile(servletName, jspFile);
  }

  @Override
  public int getSessionTimeout() {
    return delegate.getSessionTimeout();
  }

  @Override
  public void setSessionTimeout(int sessionTimeout) {
    delegate.setSessionTimeout(sessionTimeout);
  }

  @Override
  public String getRequestCharacterEncoding() {
    return delegate.getRequestCharacterEncoding();
  }

  @Override
  public void setRequestCharacterEncoding(String encoding) {
    delegate.setRequestCharacterEncoding(encoding);
  }

  @Override
  public String getResponseCharacterEncoding() {
    return delegate.getResponseCharacterEncoding();
  }

  @Override
  public void setResponseCharacterEncoding(String encoding) {
    delegate.setResponseCharacterEncoding(encoding);
  }

}
