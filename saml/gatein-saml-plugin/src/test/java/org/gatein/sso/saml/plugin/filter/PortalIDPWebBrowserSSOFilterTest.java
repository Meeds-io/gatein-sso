package org.gatein.sso.saml.plugin.filter;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mockito.internal.verification.VerificationModeFactory;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.web.filters.IDPFilter;

import junit.framework.TestCase;

public class PortalIDPWebBrowserSSOFilterTest extends TestCase {

  public void testLoginRedirect() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    PortalIDPWebBrowserSSOFilter idpWebBrowserSSOFilter = mock(PortalIDPWebBrowserSSOFilter.class);

    // When
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(request.getSession()).thenReturn(httpSession);
    when(request.getSession(anyBoolean())).thenReturn(httpSession);
    when(request.getParameter(GeneralConstants.SAML_REQUEST_KEY)).thenReturn("SOME SAML REQUEST");
    when(request.getRequestURI()).thenReturn("/portal");
    when(httpSession.getId()).thenReturn("fakeHttpSession");
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");

    doNothing().when(((IDPFilter)idpWebBrowserSSOFilter)).doFilter(request, response, chain);
    doCallRealMethod().when(idpWebBrowserSSOFilter).doFilter(request, response, chain);

    idpWebBrowserSSOFilter.init(filterConfig);
    idpWebBrowserSSOFilter.doFilter(request, response, chain);
    // Then
    verify(response, VerificationModeFactory.times(1)).sendRedirect(startsWith("/portal/dologin?initialURI="));
    verify(chain, VerificationModeFactory.times(0)).doFilter(request, response);
  }

  public void testSAMLLogin() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletRequest originalRequest = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    PortalIDPWebBrowserSSOFilter idpWebBrowserSSOFilter = mock(PortalIDPWebBrowserSSOFilter.class);

    // When
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(request.getSession()).thenReturn(httpSession);
    when(request.getSession(anyBoolean())).thenReturn(httpSession);
    when(httpSession.getAttribute(PortalIDPWebBrowserSSOFilter.ORIGINAL_HTTP_SERVLET_REQUEST_PARAM)).thenReturn(originalRequest);
    when(request.getRequestURI()).thenReturn("/portal");
    when(httpSession.getId()).thenReturn("fakeHttpSession");
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");
    when(idpWebBrowserSSOFilter.getInitParameter(GeneralConstants.ROLES)).thenReturn("users");

    doNothing().when(((IDPFilter)idpWebBrowserSSOFilter)).doFilter(request, response, chain);
    doCallRealMethod().when(idpWebBrowserSSOFilter).doFilter(request, response, chain);

    idpWebBrowserSSOFilter.init(filterConfig);
    idpWebBrowserSSOFilter.doFilter(request, response, chain);

    // Then
    verify(response, VerificationModeFactory.times(0)).sendRedirect(any());
    verify(chain, VerificationModeFactory.times(0)).doFilter(request, response);
    verify(httpSession, VerificationModeFactory.times(1)).removeAttribute(PortalIDPWebBrowserSSOFilter.ORIGINAL_HTTP_SERVLET_REQUEST_PARAM);
  }
}
