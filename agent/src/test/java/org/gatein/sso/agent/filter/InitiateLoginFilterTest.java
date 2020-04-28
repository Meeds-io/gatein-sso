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
package org.gatein.sso.agent.filter;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
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

import org.exoplatform.commons.utils.PropertyManager;

import junit.framework.TestCase;

public class InitiateLoginFilterTest extends TestCase {

  public void testDoFilterNoRedirect() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    InitiateLoginFilter initiateLoginFilter = mock(InitiateLoginFilter.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    // When
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");

    doNothing().when(initiateLoginFilter).processSSOToken(request, response);

    doCallRealMethod().when(initiateLoginFilter).doFilter(request, response, chain);
    doCallRealMethod().when(initiateLoginFilter).getLoginRedirectUrl(request);

    initiateLoginFilter.init(filterConfig);
    initiateLoginFilter.doFilter(request, response, chain);

    // Then
    verify(response, VerificationModeFactory.times(0)).sendRedirect(anyString());
    verify(chain, VerificationModeFactory.times(1)).doFilter(request, response);
  }

  public void testDoFilterSendRedirectDoLogin() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession httpSession = mock(HttpSession.class);
    FilterChain chain = mock(FilterChain.class);

    InitiateLoginFilter initiateLoginFilter = mock(InitiateLoginFilter.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    // When
    when(request.getSession()).thenReturn(httpSession);
    when(httpSession.getId()).thenReturn("fakeHttpSession");
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");

    doNothing().when(initiateLoginFilter).processSSOToken(request, response);
    doCallRealMethod().when(initiateLoginFilter).doFilter(request, response, chain);
    doCallRealMethod().when(initiateLoginFilter).getLoginRedirectUrl(request);
    doReturn("/portal/dologin").when(initiateLoginFilter).getInitParameter("loginUrl");
    doCallRealMethod().when(initiateLoginFilter).initImpl();

    initiateLoginFilter.init(filterConfig);
    initiateLoginFilter.doFilter(request, response, chain);

    // Then
    verify(response, VerificationModeFactory.times(1)).sendRedirect(startsWith("/portal/dologin?"));
    verify(chain, VerificationModeFactory.times(0)).doFilter(request, response);
  }

  public void testSendRedirectSSO() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    InitiateLoginFilter initiateLoginFilter = mock(InitiateLoginFilter.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    // When
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");
    doNothing().when(initiateLoginFilter).processSSOToken(request, response);
    doCallRealMethod().when(initiateLoginFilter).doFilter(request, response, chain);
    doCallRealMethod().when(initiateLoginFilter).getLoginRedirectUrl(request);
    doReturn("/portal/dologin").when(initiateLoginFilter).getInitParameter("loginUrl");
    doCallRealMethod().when(initiateLoginFilter).initImpl();
    when(request.getAttribute(eq("abort"))).thenReturn("true");

    // Then
    initiateLoginFilter.init(filterConfig);
    initiateLoginFilter.doFilter(request, response, chain);
    verify(response, VerificationModeFactory.times(1)).sendRedirect(eq("/portal/sso"));
    verify(chain, VerificationModeFactory.times(0)).doFilter(request, response);
  }

  public void testSendRedirectSAMLSSO() throws Exception {
    // Given
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    InitiateLoginFilter initiateLoginFilter = mock(InitiateLoginFilter.class);
    FilterConfig filterConfig = mock(FilterConfig.class);
    ServletContext servletContext = mock(ServletContext.class);

    // When
    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });
    when(filterConfig.getServletContext()).thenReturn(servletContext);
    when(servletContext.getServletContextName()).thenReturn("portal");
    when(servletContext.getContextPath()).thenReturn("/portal");
    when(request.getContextPath()).thenReturn("/portal");

    doNothing().when(initiateLoginFilter).processSSOToken(request, response);

    doCallRealMethod().when(initiateLoginFilter).doFilter(request, response, chain);
    doCallRealMethod().when(initiateLoginFilter).getLoginRedirectUrl(request);

    doReturn("/portal/dologin").when(initiateLoginFilter).getInitParameter("loginUrl");
    doCallRealMethod().when(initiateLoginFilter).initImpl();
    PropertyManager.setProperty("gatein.sso.uri.suffix", "samlSSO");

    when(response.encodeRedirectURL(any())).thenAnswer(new Answer<String>() {
      public String answer(InvocationOnMock invocation) throws Throwable {
        return (String) invocation.getArguments()[0];
      }
    });

    when(request.getAttribute(eq("abort"))).thenReturn("true");
    initiateLoginFilter.init(filterConfig);
    initiateLoginFilter.doFilter(request, response, chain);

    // Then
    verify(response, VerificationModeFactory.times(1)).sendRedirect(eq("/portal/samlSSO"));
    verify(chain, VerificationModeFactory.times(0)).doFilter(request, response);
  }
}
