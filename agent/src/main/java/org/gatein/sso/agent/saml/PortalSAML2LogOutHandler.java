/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.gatein.sso.agent.saml;

import javax.servlet.http.HttpSession;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.wci.ServletContainerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2LogOutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.picketlink.common.exceptions.ProcessingException;
import javax.servlet.http.Cookie;

import java.net.URI;
import java.security.Principal;

/**
 * Extension of {@link SAML2LogOutHandler} because we need to enforce WCI (crossContext) logout in portal environment.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PortalSAML2LogOutHandler extends SAML2LogOutHandler
{
  private static final String COOKIE_NAME = "rememberme";

  private static final String OAUTH_COOKIE_NAME = "oauth_rememberme";

  private static final String JSESSIONIDSSO_COOKIE_NAME = "JSESSIONIDSSO";

  private final SPLogOutHandler sp = new SPLogOutHandler();

  private static Log          log               = ExoLogger.getLogger(PortalSAML2LogOutHandler.class);
   
   @Override
   public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException
   {
      if (request.getSAML2Object() instanceof LogoutRequestType == false)
      {
         return;
      }
      
      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpServletResponse servletResponse = httpContext.getResponse();
      
      // Handle SAML logout request by superclass
      super.handleRequestType(request, response);

      // Check if session has been invalidated by superclass. If yes,we need to perform "full" logout at portal level by call WCI logout.
      if (servletRequest.getSession(false) == null)
      {
         portalLogout(servletRequest, servletResponse);
      }
   }

   @Override
   public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
         throws ProcessingException
   {
      //We do not handle any ResponseType (authentication etc)
      if (request.getSAML2Object() instanceof ResponseType)
         return;

      if (request.getSAML2Object() instanceof StatusResponseType == false)
         return;


      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpServletResponse servletResponse = httpContext.getResponse();

      // Handle SAML logout response by superclass
      super.handleStatusResponseType(request, response);

      // Check if session has been invalidated by superclass. If yes,we need to perform "full" logout at portal level by call WCI logout.
      if (servletRequest.getSession(false) == null)
      {
         portalLogout(servletRequest, servletResponse);
      }

   }


  public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
    if (request.getTypeOfRequestToBeGenerated() == null) {
      return;
    }
    if (SAML2HandlerRequest.GENERATE_REQUEST_TYPE.LOGOUT != request.getTypeOfRequestToBeGenerated())
      return;

    if (getType() == HANDLER_TYPE.IDP) {
      super.generateSAMLRequest(request, response);
    } else {
      sp.generateSAMLRequest(request, response);
    }
  }
   /**
    * Performs portal logout by calling WCI logout.
    * 
    * @param request
    * @param response
    */
   protected void portalLogout(HttpServletRequest request, HttpServletResponse response)
   {
      // Workaround: we need to temporary "restore" session to enforce crossContext logout at WCI layer
      request.getSession(true);

      try
      {
        if (request.getRemoteUser()!=null) {
          ServletContainerFactory.getServletContainer().logout(request, response);
        }
      }
      catch (Exception e)
      {
         log.warn("Session has been invalidated but WCI logout failed.", e);
      }

      // Remove rememberme cookie
      Cookie cookie = new Cookie(COOKIE_NAME, "");
      cookie.setPath("/");
      cookie.setMaxAge(0);
      response.addCookie(cookie);

     // Remove JSESSIONIDSSO cookie
     Cookie jsessionIdSSOCookie = new Cookie(JSESSIONIDSSO_COOKIE_NAME, "");
     jsessionIdSSOCookie.setPath("/");
     jsessionIdSSOCookie.setMaxAge(0);
     response.addCookie(jsessionIdSSOCookie);
  
      // Remove oauth cookie
      Cookie oauthCookie = new Cookie(OAUTH_COOKIE_NAME, "");
      oauthCookie.setPath(request.getContextPath());
      oauthCookie.setMaxAge(0);
      response.addCookie(oauthCookie);
   }


  private class SPLogOutHandler {
    public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
      // Generate the LogOut Request
      SAML2Request samlRequest = new SAML2Request();

      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest httpRequest = httpContext.getRequest();
      Principal userPrincipal = getUserPrincipal(httpRequest);
      if (userPrincipal == null) {
        return;
      }
      try {
        LogoutRequestType lot = samlRequest.createLogoutRequest(request.getIssuer().getValue());

        NameIDType nameID = new NameIDType();
        nameID.setValue(userPrincipal.getName());
        lot.setNameID(nameID);

        SPType spConfiguration = getSPConfiguration();
        String logoutUrl = spConfiguration.getLogoutUrl();

        if (logoutUrl == null) {
          logoutUrl = getIdentityURL(request);
        }

        lot.setDestination(URI.create(logoutUrl));
        response.setDestination(logoutUrl);
        response.setResultingDocument(samlRequest.convert(lot));
        response.setSendRequest(true);
      } catch (Exception e) {
        throw logger.processingError(e);
      }
    }

    public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
        throws ProcessingException {
      // Handler a log out response from IDP
      StatusResponseType statusResponseType = (StatusResponseType) request.getSAML2Object();

      checkDestination(statusResponseType.getDestination(), getSPConfiguration().getServiceURL());

      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpSession session = servletRequest.getSession(false);

      // TODO: Deal with partial logout report

      StatusType statusType = statusResponseType.getStatus();
      StatusCodeType statusCode = statusType.getStatusCode();
      URI statusCodeValueURI = statusCode.getValue();
      boolean success = false;
      if (statusCodeValueURI != null) {
        String statusCodeValue = statusCodeValueURI.toString();
        if (JBossSAMLURIConstants.STATUS_SUCCESS.get().equals(statusCodeValue)) {
          success = true;
          session.invalidate();
        }
      }
    }

    public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
      SAML2Object samlObject = request.getSAML2Object();
      if (samlObject instanceof LogoutRequestType == false)
        return;
      //get the configuration to handle a logout request from idp and set the correct response location
      SPType spConfiguration = getSPConfiguration();

      LogoutRequestType logOutRequest = (LogoutRequestType) samlObject;

      checkDestination(logOutRequest.getDestination(), spConfiguration.getServiceURL());

      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpSession session = servletRequest.getSession(false);

      String relayState = servletRequest.getParameter("RelayState");

      session.invalidate(); // Invalidate the current session at the SP

      // Generate a Logout Response
      StatusResponseType statusResponse = null;
      try {
        statusResponse = new StatusResponseType(IDGenerator.create("ID_"), XMLTimeUtil.getIssueInstant());
      } catch (ConfigurationException e) {
        throw logger.processingError(e);
      }

      // Status
      StatusType statusType = new StatusType();
      StatusCodeType statusCodeType = new StatusCodeType();
      statusCodeType.setValue(URI.create(JBossSAMLURIConstants.STATUS_RESPONDER.get()));

      // 2nd level status code
      StatusCodeType status2ndLevel = new StatusCodeType();
      status2ndLevel.setValue(URI.create(JBossSAMLURIConstants.STATUS_SUCCESS.get()));
      statusCodeType.setStatusCode(status2ndLevel);

      statusType.setStatusCode(statusCodeType);

      statusResponse.setStatus(statusType);

      statusResponse.setInResponseTo(logOutRequest.getID());

      statusResponse.setIssuer(request.getIssuer());

      String logoutResponseLocation = spConfiguration.getLogoutResponseLocation();

      if (logoutResponseLocation == null) {
        response.setDestination(logOutRequest.getIssuer().getValue());
      } else {
        response.setDestination(logoutResponseLocation);
      }

      statusResponse.setDestination(response.getDestination());

      SAML2Response saml2Response = new SAML2Response();
      try {
        response.setResultingDocument(saml2Response.convert(statusResponse));
      } catch (Exception je) {
        throw logger.processingError(je);
      }

      response.setRelayState(relayState);
      response.setDestination(logOutRequest.getIssuer().getValue());
      response.setSendRequest(false);
    }
  }

  private SPType getSPConfiguration() {
    return (SPType) getProviderconfig();
  }

  Principal getUserPrincipal(HttpServletRequest request) {
    HttpSession session = request.getSession();
    Principal userPrincipal = request.getUserPrincipal();
    if (userPrincipal ==  null) {
      userPrincipal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);
    }

    return userPrincipal;
  }

  private String getIdentityURL(SAML2HandlerRequest request) {
    SPType spConfiguration = getSPConfiguration();
    HTTPContext httpContext = (HTTPContext) request.getContext();
    HttpServletRequest httpServletRequest = httpContext.getRequest();
    String desiredIdP = (String) httpServletRequest.getAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP);

    if (desiredIdP != null) {
      return desiredIdP;
    }

    return spConfiguration.getIdentityURL();
  }
   
}
