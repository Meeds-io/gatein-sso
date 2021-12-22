/**
 * 
 */
package org.gatein.sso.agent.filter;

import java.io.IOException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.GenericAgent;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;
import org.gatein.sso.agent.opensso.OpenSSOAgent;
import org.gatein.wci.security.Credentials;

import org.exoplatform.commons.utils.PropertyManager;

/**
 * @author soshah
 */
public class InitiateLoginFilter extends AbstractSSOInterceptor {
  private static Log       log                                = ExoLogger.getLogger(InitiateLoginFilter.class);

  private static final int DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS = 3;

  private String           ssoServerUrl;

  private String           ssoCookieName;

  private String           loginUrl;

  private int              maxNumberOfLoginErrors;

  private boolean          attachUsernamePasswordToLoginURL;

  private OpenSSOAgent     openSSOAgent;

  @Override
  protected void initImpl() {
    this.ssoServerUrl = getInitParameter("ssoServerUrl");
    this.ssoCookieName = getInitParameter("ssoCookieName");
    this.loginUrl = getInitParameter("loginUrl");

    String maxNumberOfLoginErrorsConfig = getInitParameter("maxNumberOfLoginErrors");
    this.maxNumberOfLoginErrors = maxNumberOfLoginErrorsConfig == null ? DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS
                                                                       : Integer.parseInt(maxNumberOfLoginErrorsConfig);

    String attachUsernamePasswordToLoginURLConfig = getInitParameter("attachUsernamePasswordToLoginURL");
    this.attachUsernamePasswordToLoginURL =
                                          attachUsernamePasswordToLoginURLConfig == null
                                              || Boolean.parseBoolean(attachUsernamePasswordToLoginURLConfig);
  }

  public void doFilter(ServletRequest request,
                       ServletResponse response,
                       FilterChain chain) throws IOException, ServletException {
    try {
      HttpServletRequest req = (HttpServletRequest) request;
      HttpServletResponse resp = (HttpServletResponse) response;

      this.processSSOToken(req, resp);

      // Redirection can be already performed from processSSOToken call
      if (resp.isCommitted()) {
        return;
      }

      String portalContext = req.getContextPath();
      if (req.getAttribute("abort") != null) {
        String ssoSuffix = PropertyManager.getProperty("gatein.sso.uri.suffix");
        if (StringUtils.isBlank(ssoSuffix)) {
          ssoSuffix = "/sso";
        }
        String ssoRedirect = portalContext + (ssoSuffix.startsWith("/") ? ssoSuffix : ("/" + ssoSuffix));
        resp.sendRedirect(ssoRedirect);
        return;
      }

      String loginRedirectURL = getLoginRedirectUrl(req);
      if (StringUtils.isBlank(loginRedirectURL)) {
        log.warn("Can't redirect to null SSO URL");
        chain.doFilter(request, response);
      } else {
        loginRedirectURL = resp.encodeRedirectURL(loginRedirectURL);
        resp.sendRedirect(loginRedirectURL);
      }
    } catch (Exception e) {
      throw new ServletException(e);
    }
  }

  @Override
  public void destroy() {
    // Nothing to proceed
  }

  protected OpenSSOAgent getOpenSSOAgent() {
    if (this.openSSOAgent == null) {
      OpenSSOAgent openssoAgent = getExoContainer().getComponentInstanceOfType(OpenSSOAgent.class);
      if (openssoAgent == null) {
        throw new IllegalStateException("OpenSSOAgent component not provided in PortalContainer");
      }

      openssoAgent.setServerUrl(ssoServerUrl);
      openssoAgent.setCookieName(ssoCookieName);
      this.openSSOAgent = openssoAgent;
    }

    return this.openSSOAgent;
  }

  protected void processSSOToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws Exception {
    try {
      // See if an OpenSSO Token was used
      getOpenSSOAgent().validateTicket(httpRequest, httpResponse);
    } catch (IllegalStateException ilse) {
      // Somehow cookie failed validation, retry by starting the opensso login
      // process again.
      // To avoid infinite loop of redirects, we are tracking maximum number
      // of SSO errors for this client
      int currentNumberOfErrors = getCountOfUnsuccessfulAttempts(httpRequest);
      log.warn("Count of login errors: " + currentNumberOfErrors);

      if (currentNumberOfErrors >= maxNumberOfLoginErrors) {
        log.warn("Max. number of login errors reached. Rethrowing exception");
        throw ilse;
      } else {
        httpRequest.setAttribute("abort", Boolean.TRUE);
      }
    }
  }

  // Tracking maximum number of SSO errors for this client in session attribute
  private int getCountOfUnsuccessfulAttempts(HttpServletRequest httpRequest) {
    Integer currentNumberOfErrors = (Integer) httpRequest.getSession().getAttribute("InitiateLoginFilter.currentNumberOfErrors");
    if (currentNumberOfErrors == null) {
      currentNumberOfErrors = 0;
    }

    currentNumberOfErrors = currentNumberOfErrors + 1;
    httpRequest.getSession().setAttribute("InitiateLoginFilter.currentNumberOfErrors", currentNumberOfErrors);

    return currentNumberOfErrors;
  }

  protected String getLoginRedirectUrl(HttpServletRequest req) {
    if (this.loginUrl == null) {
      return null;
    }
    StringBuilder url = new StringBuilder(this.loginUrl);

    if (attachUsernamePasswordToLoginURL) {
      String fakePassword = req.getSession().getId() + "_" + System.currentTimeMillis();

      // Try to use username from authenticated credentials
      String username;
      Credentials creds = (Credentials) req.getSession().getAttribute(GenericAgent.AUTHENTICATED_CREDENTIALS);
      if (creds != null) {
        username = creds.getUsername();
      } else {
        // Fallback to fakePassword, but this should't happen (credentials
        // should always be available when this method is called)
        username = fakePassword;
      }

      // Use sessionId and system millis as password (similar like spnego is
      // doing)
      url.append("?username=").append(username).append("&password=").append(fakePassword);
    }

    return url.toString();
  }
}
