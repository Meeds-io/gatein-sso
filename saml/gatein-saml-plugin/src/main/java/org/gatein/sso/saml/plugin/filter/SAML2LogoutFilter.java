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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.filter.api.SSOInterceptor;
import org.gatein.sso.agent.filter.api.SSOInterceptorInitializationContext;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.web.filters.SPFilter;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.container.util.ContainerUtil;
import org.exoplatform.container.xml.InitParams;

public class SAML2LogoutFilter extends SPFilter implements SSOInterceptor {

  public static final String                 SAML_LOGOUT_ATTRIBUTE = "SAML_LOGOUT_IN_PROGRESS";

  private static final Logger                 log                   = LoggerFactory.getLogger(SAML2LogoutFilter.class);

  public static final String                  COOKIE_NAME           = "rememberme";

  public static final String                  OAUTH_COOKIE_NAME     = "oauth_rememberme";

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
  public void doFilter(ServletRequest servletRequest,
                       ServletResponse servletResponse,
                       FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;
    request.setCharacterEncoding("UTF-8");
    if (isPortalLogoutInProgress(request)) {
      if(StringUtils.isBlank(getPortalLogoutURLFromSession(request))) {
        // Step 1 : Begin -  call logout action
        HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request) {
          @Override
          public String getParameter(String name) {
            if (StringUtils.equals("GLO", name)) {
              return "true";
            }
            return super.getParameter(name);
          }
        };
        // Step 1 : End - logout from the IDP (redirect to IDP logout URL)
        super.doFilter(requestWrapper, servletResponse, new EmptyFilterChain());
        request.getSession().setAttribute(SAML_LOGOUT_ATTRIBUTE, request.getRequestURI() + "?" + request.getQueryString());
      } else {
        // Step 3 : Call UIPortal.LogoutActionListener
        filterChain.doFilter(servletRequest, servletResponse);
        try {
          // Step 4: Ensure that the session is invalidated
          request.getSession().invalidate();
        } catch (IllegalStateException e) {
          // The session may be already invalidated
        }
      }
    } else if (isSAMLLogoutInProgress(request)) {
      // Step 2 : logout local session from the SP (redirect UIPortal.LogoutActionListener)
      response.sendRedirect(getPortalLogoutURLFromSession(request));
    } else {
      // Regular request
      filterChain.doFilter(servletRequest, servletResponse);
    }
  }

  private static String getPortalLogoutURLFromSession(HttpServletRequest request) {
    return request.getSession().getAttribute(SAML_LOGOUT_ATTRIBUTE) == null ? null
                                                                            : request.getSession()
                                                                                     .getAttribute(SAML_LOGOUT_ATTRIBUTE)
                                                                                     .toString();
  }

  public static boolean isPortalLogoutInProgress(HttpServletRequest request) {
    if (StringUtils.equals(request.getParameter("portal:action"), "Logout") && request.getRemoteUser() != null) {
      return true;
    }
    return false;
  }

  public static boolean isSAMLLogoutInProgress(HttpServletRequest request) {
    if (request.getRemoteUser() != null && StringUtils.isNotBlank(getPortalLogoutURLFromSession(request))
        && !StringUtils.equals(getPortalLogoutURLFromSession(request), "DONE")) {
      return true;
    }
    return false;
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
    this.configFile = SAMLSPServletContextWrapper.FILE_PREFIX + getInitParameter(GeneralConstants.CONFIG_FILE);
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
        ServletContext servletContext = new SAMLSPServletContextWrapper(getServletContext());
        this.config = new SAMLFilterConfig("SAML2LogoutFilter", servletContext, interceptorContext);
      } else {
        this.config = config;
      }
    }
    return this.config;
  }
}
