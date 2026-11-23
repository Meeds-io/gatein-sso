/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2026 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.picketlink.identity.federation.bindings.tomcat.sp;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Principal;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.LoginConfig;

import jakarta.servlet.http.HttpServletResponse;
import junit.framework.TestCase;

public class AbstractSPFormAuthenticatorTest extends TestCase {

  private Request  request;

  private Response response;

  @Override
  protected void setUp() throws Exception {
    request = mock(Request.class);
    response = mock(Response.class);
    Context context = mock(Context.class);
    when(request.getContext()).thenReturn(context);
    when(context.getLoginConfig()).thenReturn(new LoginConfig());
    when(request.getSessionInternal(true)).thenReturn(mock(Session.class));
  }

  public void testRestoredRequestKeepsConstraintsRefresh() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("PASSED_CONSTRAINTS_NEED_REFRESH");

    assertEquals("PASSED_CONSTRAINTS_NEED_REFRESH", authenticator.authenticateExtended(request, response));
    assertTrue(authenticator.registered);
    verify(response, never()).sendError(HttpServletResponse.SC_BAD_REQUEST);
    assertTrue(authenticator.authenticate(request, response));
  }

  public void testRestoredRequestPassed() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("PASSED");

    assertEquals("PASSED", authenticator.authenticateExtended(request, response));
    verify(response, never()).sendError(HttpServletResponse.SC_BAD_REQUEST);
  }

  public void testRestoreFailureSendsBadRequest() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("FAILED");

    assertEquals("FAILED", authenticator.authenticateExtended(request, response));
    verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST);
    assertFalse(authenticator.authenticate(request, response));
  }

  /**
   * A service provider valve whose request matches the one saved before the
   * IDP round trip, and whose restore outcome is fixed by the test.
   */
  private static class RestoringAuthenticator extends AbstractSPFormAuthenticator {

    private final AuthenticationResult restoreResult;

    private boolean                    registered;

    RestoringAuthenticator(String restoreResult) {
      this.restoreResult = AuthenticationResult.valueOf(restoreResult);
    }

    String authenticateExtended(Request request, HttpServletResponse response) throws IOException {
      return doAuthenticateExtended(request, response).name();
    }

    @Override
    protected String getContextPath() {
      return "/portal";
    }

    @Override
    protected boolean matchRequest(Request request) {
      return true;
    }

    @Override
    public AuthenticationResult restoreRequest(Request request, Session session) {
      return restoreResult;
    }

    @Override
    public void register(Request request,
                         HttpServletResponse response,
                         Principal principal,
                         String authType,
                         String username,
                         String password) {
      registered = true;
    }
  }
}
