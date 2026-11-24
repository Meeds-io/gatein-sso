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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.picketlink.common.constants.GeneralConstants;

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

  public void testSaml11ResponseKeepsConstraintsRefresh() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("PASSED_CONSTRAINTS_NEED_REFRESH");
    authenticator.matches = false;
    when(request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).thenReturn(saml11Response());

    assertEquals("PASSED_CONSTRAINTS_NEED_REFRESH", authenticator.authenticateExtended(request, response));
    assertTrue(authenticator.registered);
    assertTrue(authenticator.authenticate(request, response));
  }

  public void testSaml11ResponsePassedWhenRestorePassed() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("PASSED");
    authenticator.matches = false;
    when(request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).thenReturn(saml11Response());

    assertEquals("PASSED", authenticator.authenticateExtended(request, response));
    assertTrue(authenticator.registered);
  }

  public void testSaml11ResponsePassedWhenRestoreFailed() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("FAILED");
    authenticator.matches = false;
    when(request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).thenReturn(saml11Response());

    assertEquals("PASSED", authenticator.authenticateExtended(request, response));
    assertTrue(authenticator.registered);
  }

  public void testAlreadyAuthenticatedRequestPassed() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("FAILED");
    authenticator.matches = false;
    when(request.getUserPrincipal()).thenReturn(mock(Principal.class));

    assertEquals("PASSED", authenticator.authenticateExtended(request, response));
    assertFalse(authenticator.registered);
  }

  public void testLocalLogoutFailed() throws Exception {
    RestoringAuthenticator authenticator = new RestoringAuthenticator("PASSED");
    authenticator.matches = false;
    when(request.getParameter(GeneralConstants.LOCAL_LOGOUT)).thenReturn("true");

    assertEquals("FAILED", authenticator.authenticateExtended(request, response));
    assertTrue(authenticator.loggedOut);
    assertFalse(authenticator.authenticate(request, response));
  }

  private static String saml11Response() throws IOException {
    String xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" "
        + "ResponseID=\"_response1\" MajorVersion=\"1\" MinorVersion=\"1\" IssueInstant=\"2026-01-01T00:00:00Z\">"
        + "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AssertionID=\"_assertion1\" "
        + "MajorVersion=\"1\" MinorVersion=\"1\" Issuer=\"idp\" IssueInstant=\"2026-01-01T00:00:00Z\">"
        + "<saml:AuthenticationStatement AuthenticationMethod=\"urn:oasis:names:tc:SAML:1.0:am:password\" "
        + "AuthenticationInstant=\"2026-01-01T00:00:00Z\">"
        + "<saml:Subject><saml:NameIdentifier>john</saml:NameIdentifier></saml:Subject>"
        + "</saml:AuthenticationStatement>"
        + "</saml:Assertion></samlp:Response>";
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DeflaterOutputStream deflater = new DeflaterOutputStream(bytes, new Deflater(Deflater.DEFAULT_COMPRESSION, true))) {
      deflater.write(xml.getBytes(StandardCharsets.UTF_8));
    }
    return Base64.getEncoder().encodeToString(bytes.toByteArray());
  }

  /**
   * A service provider valve whose request matches the one saved before the
   * IDP round trip, and whose restore outcome is fixed by the test.
   */
  private static class RestoringAuthenticator extends AbstractSPFormAuthenticator {

    private final AuthenticationResult restoreResult;

    private boolean                    registered;

    private boolean                    matches  = true;

    private boolean                    loggedOut;

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
      return matches;
    }

    @Override
    protected void sendToLogoutPage(Request request, HttpServletResponse response, Session session) {
      loggedOut = true;
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
