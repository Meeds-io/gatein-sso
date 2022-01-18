package org.gatein.sso.saml.plugin.filter;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.filter.api.SSOInterceptor;
import org.gatein.sso.agent.filter.api.SSOInterceptorInitializationContext;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.web.filters.IDPFilter;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.container.util.ContainerUtil;
import org.exoplatform.container.xml.InitParams;

public class PortalIDPWebBrowserSSOFilter extends IDPFilter implements SSOInterceptor {

  public static final String                 ORIGINAL_HTTP_SERVLET_REQUEST_PARAM = "OriginalHttpServletRequest";

  private static final Log                    log                                 =
                                                  ExoLogger.getLogger(PortalIDPWebBrowserSSOFilter.class);

  /**
   * The filter configuration
   */
  protected FilterConfig                      config;

  /**
   * The Servlet context name
   */
  protected String                            servletContextName;

  /**
   * Indicates if we need a portal environment.
   */
  private volatile Boolean                    requirePortalEnvironment;

  private SSOInterceptorInitializationContext interceptorContext;

  /**
   * {@inheritDoc}
   */
  public final void init(FilterConfig config) throws ServletException {
    this.config = getFilterConfig(config);
    this.servletContextName = ContainerUtil.getServletContextName(config.getServletContext());
    afterInit(config);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;
    HttpSession session = httpServletRequest.getSession(true);

    // get an authenticated user or tries to authenticate if this is a
    // authentication request
    Principal userPrincipal = httpServletRequest.getUserPrincipal();
    String samlRequestMessage = (String) request.getParameter(GeneralConstants.SAML_REQUEST_KEY);

    // If this is a SAML Request but no user is authenticated, then redirect to
    // login page
    if (userPrincipal == null && StringUtils.isNotBlank(samlRequestMessage)) {
      session.setAttribute(ORIGINAL_HTTP_SERVLET_REQUEST_PARAM, httpServletRequest);

      httpServletResponse.sendRedirect("/" + servletContextName + "/dologin?initialURI="
          + URLEncoder.encode(httpServletRequest.getRequestURI(), "UTF-8"));
      return;
    } else {
      final HttpServletRequest originalHttpServletRequest =
                                                          (HttpServletRequest) session.getAttribute(ORIGINAL_HTTP_SERVLET_REQUEST_PARAM);
      if (originalHttpServletRequest != null) {
        request = new SAMLHTTPRequestWrapper(httpServletRequest, originalHttpServletRequest);
        session.removeAttribute(ORIGINAL_HTTP_SERVLET_REQUEST_PARAM);
      }
    }

    super.doFilter(request, response, chain);
  }

  /**
   * @return Gives the {@link ExoContainer} that fits best with the current
   *         context
   */
  private final ExoContainer getContainer() {
    ExoContainer container = ExoContainerContext.getCurrentContainer();
    if (container instanceof RootContainer) {
      container = interceptorContext.getExoContainer();
    }
    if (container instanceof RootContainer) {
      // The top container is a RootContainer, thus we assume that we are in a
      // portal mode
      container = PortalContainer.getInstance();
    }
    // The container is a PortalContainer or a StandaloneContainer
    return container;
  }

  /**
   * Method is invoked if we are performing initialization through servlet api
   * (web filter)
   */
  private final void afterInit(FilterConfig filterConfig) throws ServletException {
    this.interceptorContext = new SSOInterceptorInitializationContext(filterConfig, null, null);
    log.debug("Interceptor initialized with context " + interceptorContext);
    try {
      initImpl();
    } catch (ServletException e) {
      log.error("Error initializing SAML Filter", e);
    }
  }

  /**
   * Method is invoked if we are performing initialization through exo kernel
   */
  public final void initWithParams(InitParams params, ExoContainerContext containerContext) {
    this.interceptorContext = new SSOInterceptorInitializationContext(null, params, containerContext);
    this.servletContextName = containerContext.getPortalContainerName();
    log.debug("Interceptor initialized with context " + interceptorContext);
    try {
      initImpl();
    } catch (ServletException e) {
      log.error("Error initializing SAML Filter", e);
    }
  }

  /**
   * This method needs to be implemented by conrete filter. Filter should obtain
   * it's init parameters by calling {@link #getInitParameter(String)}. This
   * works in both types of initialization (Case1: Filter initialization through
   * kernel, Case2: initialization through servlet API)
   * 
   * @throws ServletException an init exception happens when calling super class init method
   */
  protected void initImpl() throws ServletException {
    FilterConfig filterConfig = getFilterConfig(null);
    if (this.servletContextName == null) {
      this.servletContextName = ContainerUtil.getServletContextName(getServletContext());
    }
    filterConfig.getServletContext().setInitParameter(GeneralConstants.CONFIG_FILE,
                                                      getInitParameter(GeneralConstants.CONFIG_FILE));
    super.init(filterConfig);
  }

  /**
   * Read init parameter (works for both kernel initialization or Servlet API
   * initialization)
   *
   * @param paramName parameter name
   * @return parameter value
   */
  protected String getInitParameter(String paramName) {
    return interceptorContext.getInitParameter(paramName);
  }

  /**
   * Indicates if it requires that a full portal environment must be set
   * 
   * @return <code>true</code> if it requires the portal environment
   *         <code>false</code> otherwise.
   */
  protected boolean requirePortalEnvironment() {
    if (requirePortalEnvironment == null) {
      synchronized (this) {
        if (requirePortalEnvironment == null) {
          this.requirePortalEnvironment = PortalContainer.isPortalContainerName(servletContextName);
        }
      }
    }
    return requirePortalEnvironment.booleanValue();
  }

  /**
   * @return the current {@link ServletContext}
   */
  protected ServletContext getServletContext() {
    if (requirePortalEnvironment()) {
      ExoContainer container = getContainer();
      if (container instanceof PortalContainer) {
        return ((PortalContainer) container).getPortalContext();
      }
    }
    if (this.config != null) {
      return this.config.getServletContext();
    }
    return null;
  }

  private FilterConfig getFilterConfig(FilterConfig config) {
    if (this.config == null) {
      if (config == null) {
        this.config = new SAMLFilterConfig("PortalIDPWebBrowserSSOFilter", getServletContext(), interceptorContext);
      } else {
        this.config = config;
      }
    }
    return this.config;
  }
}
