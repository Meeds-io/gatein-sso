package org.gatein.sso.saml.plugin.filter;

import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.mockito.internal.verification.VerificationModeFactory;
import org.picketlink.common.constants.GeneralConstants;

import junit.framework.TestCase;

public class SAML2LogoutFilterTest extends TestCase {

  public void testLogoutProcessStep1() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    SAML2LogoutFilter saml2LogoutFilter = mock(SAML2LogoutFilter.class);

    // When
    when(request.getRequestURI()).thenReturn("/portal");
    when(request.getQueryString()).thenReturn("portal:action=Logout");
    when(request.getParameter("portal:action")).thenReturn("Logout");
    when(request.getRemoteUser()).thenReturn("root");
    when(request.getSession()).thenReturn(httpSession);
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.CONFIG_FILE)).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                                .getPath());
    when(servletContext.getResourceAsStream(startsWith("file:/"))).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                        .openStream());
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.ROLES)).thenReturn("users");
    when(filterConfig.getInitParameter(GeneralConstants.ROLE_VALIDATOR)).thenReturn("org.picketlink.identity.federation.web.roles.DefaultRoleValidator");
    System.setProperty("picketlink.keystore", getClass().getResource("/jbid_test_keystore.jks").getPath());

    doCallRealMethod().when(saml2LogoutFilter).doFilter(request, response, chain);
    doCallRealMethod().when(saml2LogoutFilter).initImpl();

    saml2LogoutFilter.init(filterConfig);
    saml2LogoutFilter.doFilter(request, response, chain);

    verify(httpSession, VerificationModeFactory.times(1)).setAttribute(eq(SAML2LogoutFilter.SAML_LOGOUT_ATTRIBUTE),
                                                                       eq("/portal?portal:action=Logout"));
  }

  public void testLogoutProcessStep2() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    SAML2LogoutFilter saml2LogoutFilter = mock(SAML2LogoutFilter.class);

    // When
    when(request.getRequestURI()).thenReturn("/portal");
    when(httpSession.getAttribute(SAML2LogoutFilter.SAML_LOGOUT_ATTRIBUTE)).thenReturn("/portal?portal:action=Logout");
    when(request.getRemoteUser()).thenReturn("root");
    when(request.getSession()).thenReturn(httpSession);
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.CONFIG_FILE)).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                                .getPath());
    when(servletContext.getResourceAsStream(startsWith("file:/"))).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                        .openStream());
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.ROLES)).thenReturn("users");
    when(filterConfig.getInitParameter(GeneralConstants.ROLE_VALIDATOR)).thenReturn("org.picketlink.identity.federation.web.roles.DefaultRoleValidator");
    System.setProperty("picketlink.keystore", getClass().getResource("/jbid_test_keystore.jks").getPath());

    doCallRealMethod().when(saml2LogoutFilter).doFilter(request, response, chain);
    doCallRealMethod().when(saml2LogoutFilter).initImpl();

    saml2LogoutFilter.init(filterConfig);
    saml2LogoutFilter.doFilter(request, response, chain);

    verify(response, VerificationModeFactory.times(1)).sendRedirect(eq("/portal?portal:action=Logout"));
  }

  public void testLogoutProcessStep3AndStep4() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    SAML2LogoutFilter saml2LogoutFilter = mock(SAML2LogoutFilter.class);

    // When
    when(request.getRequestURI()).thenReturn("/portal");
    when(request.getQueryString()).thenReturn("portal:action=Logout");
    when(request.getParameter("portal:action")).thenReturn("Logout");
    when(httpSession.getAttribute(SAML2LogoutFilter.SAML_LOGOUT_ATTRIBUTE)).thenReturn("/portal?portal:action=Logout");
    when(request.getRemoteUser()).thenReturn("root");
    when(request.getSession()).thenReturn(httpSession);
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.CONFIG_FILE)).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                                .getPath());
    when(servletContext.getResourceAsStream(startsWith("file:/"))).thenReturn(getClass().getResource("/picketlink-sp.xml")
                                                                                        .openStream());
    when(saml2LogoutFilter.getInitParameter(GeneralConstants.ROLES)).thenReturn("users");
    when(filterConfig.getInitParameter(GeneralConstants.ROLE_VALIDATOR)).thenReturn("org.picketlink.identity.federation.web.roles.DefaultRoleValidator");
    System.setProperty("picketlink.keystore", getClass().getResource("/jbid_test_keystore.jks").getPath());

    doCallRealMethod().when(saml2LogoutFilter).doFilter(request, response, chain);
    doCallRealMethod().when(saml2LogoutFilter).initImpl();

    saml2LogoutFilter.init(filterConfig);
    saml2LogoutFilter.doFilter(request, response, chain);

    verify(chain, VerificationModeFactory.times(1)).doFilter(request, response);
    verify(httpSession, VerificationModeFactory.times(1)).invalidate();
  }
}
