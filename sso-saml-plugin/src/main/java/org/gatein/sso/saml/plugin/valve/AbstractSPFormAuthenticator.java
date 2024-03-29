package org.gatein.sso.saml.plugin.valve;

import static org.gatein.sso.saml.plugin.valve.AbstractSAML11SPRedirectFormAuthenticator.handleSAML11UnsolicitedResponse;
import static org.picketlink.common.util.StringUtil.isNotNull;
import static org.picketlink.common.util.StringUtil.isNullOrEmpty;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.exoplatform.commons.utils.ListAccess;
import org.exoplatform.services.organization.Query;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserHandler;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.fed.AssertionExpiredException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.config.federation.AuthPropertyType;
import org.picketlink.config.federation.KeyProviderType;
import org.picketlink.identity.federation.bindings.tomcat.sp.holder.ServiceProviderSAMLContext;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditEvent;
import org.picketlink.identity.federation.core.audit.PicketLinkAuditEventType;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v2.holders.DestinationInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.process.ServiceProviderBaseProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLRequestProcessor;
import org.picketlink.identity.federation.web.process.ServiceProviderSAMLResponseProcessor;
import org.picketlink.identity.federation.web.util.HTTPRedirectUtil;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil.RedirectBindingUtilDestHolder;
import org.picketlink.identity.federation.web.util.ServerDetector;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.services.organization.Membership;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.security.MembershipEntry;
import org.exoplatform.services.security.MembershipHashSet;
import org.exoplatform.services.security.RolesExtractor;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Abstract class to be extended by Service Provider valves to handle SAML
 * requests and responses. forked from
 * org.picketlink.identity.federation.bindings.tomcat.sp.AbstractSPFormAuthenticator
 * and made compatible with Tomcat 8.5 since picketlink doesn't provide such a
 * support
 */
public abstract class AbstractSPFormAuthenticator extends BaseFormAuthenticator {
  private static final String FORM_PRINCIPAL_NOTE = "org.apache.catalina.authenticator.PRINCIPAL";

  protected boolean           jbossEnv            = false;

  AbstractSPFormAuthenticator() {
    super();
    ServerDetector detector = new ServerDetector();
    jbossEnv = detector.isJboss();
  }

  /*
   * (non-Javadoc)
   * @see
   * org.picketlink.identity.federation.bindings.tomcat.sp.BaseFormAuthenticator
   * #processStart()
   */
  @Override
  protected void startPicketLink() throws LifecycleException {
    super.startPicketLink();
    initKeyProvider(context);
  }

  /**
   * <p>
   * Send the request to the IDP. Subclasses should override this method to
   * implement how requests must be sent to the IDP.
   * </p>
   *
   * @param destination idp url
   * @param samlDocument request or response document
   * @param relayState used in SAML Workflow
   * @param response Apache Catalina HTTP Response
   * @param request Apache Catalina HTTP Request
   * @param willSendRequest are we sending Request or Response to IDP
   * @param destinationQueryStringWithSignature used only with Redirect binding
   *          and with signature enabled.
   * @throws ProcessingException Exception to indicate a server processing error
   * @throws ConfigurationException Exception indicating an issue with the
   *           configuration
   * @throws IOException I/O exception
   */
  protected void sendRequestToIDP(String destination,
                                  Document samlDocument,
                                  String relayState,
                                  Request request,
                                  Response response,
                                  boolean willSendRequest,
                                  String destinationQueryStringWithSignature) throws ProcessingException,
                                                                              ConfigurationException,
                                                                              IOException {

    if (isAjaxRequest(request) && request.getUserPrincipal() == null) {
      response.sendError(Response.SC_FORBIDDEN);
    } else {
      if (isHttpPostBinding()) {
        sendHttpPostBindingRequest(destination, samlDocument, relayState, response, willSendRequest);
      } else {
        sendHttpRedirectRequest(destination,
                                samlDocument,
                                relayState,
                                response,
                                willSendRequest,
                                destinationQueryStringWithSignature);
      }
    }
  }

  /**
   * <p>
   * Sends a HTTP Redirect request to the IDP.
   * </p>
   *
   * @param destination idp url
   * @param samlDocument SAML request document
   * @param relayState used in SAML Workflow
   * @param response Apache Catalina HTTP Response
   * @param willSendRequest are we sending Request or Response to IDP
   * @param destinationQueryStringWithSignature used only with Redirect binding
   *          and with signature enabled.
   * @throws IOException I/O exception
   * @throws UnsupportedEncodingException when decoding SAML Message
   * @throws ConfigurationException Exception indicating an issue with the
   *           configuration
   * @throws ProcessingException Exception to indicate a server processing error
   */
  protected void sendHttpRedirectRequest(String destination,
                                         Document samlDocument,
                                         String relayState,
                                         Response response,
                                         boolean willSendRequest,
                                         String destinationQueryStringWithSignature) throws IOException,
                                                                                     ProcessingException,
                                                                                     ConfigurationException {
    String destinationQueryString = null;

    // We already have queryString with signature from
    // SAML2SignatureGenerationHandler
    if (destinationQueryStringWithSignature != null) {
      destinationQueryString = destinationQueryStringWithSignature;
    } else {
      String samlMessage = DocumentUtil.getDocumentAsString(samlDocument);
      String base64Request = RedirectBindingUtil.deflateBase64URLEncode(samlMessage.getBytes("UTF-8"));
      destinationQueryString = RedirectBindingUtil.getDestinationQueryString(base64Request, relayState, willSendRequest);
    }

    RedirectBindingUtilDestHolder holder = new RedirectBindingUtilDestHolder();

    holder.setDestination(destination).setDestinationQueryString(destinationQueryString);

    HTTPRedirectUtil.sendRedirectForRequestor(RedirectBindingUtil.getDestinationURL(holder), response);
  }

  /**
   * <p>
   * Sends a HTTP POST request to the IDP.
   * </p>
   *
   * @param destination idp url
   * @param samlDocument request or response document
   * @param relayState used in SAML Workflow
   * @param response Apache Catalina HTTP Response
   * @param willSendRequest are we sending Request or Response to IDP
   * @throws ProcessingException Exception to indicate a server processing error
   * @throws ConfigurationException Exception indicating an issue with the
   *           configuration
   * @throws IOException I/O exception
   */
  protected void sendHttpPostBindingRequest(String destination,
                                            Document samlDocument,
                                            String relayState,
                                            Response response,
                                            boolean willSendRequest) throws ProcessingException,
                                                                     IOException,
                                                                     ConfigurationException {
    String samlMessage = PostBindingUtil.base64Encode(DocumentUtil.getDocumentAsString(samlDocument));

    DestinationInfoHolder destinationHolder = new DestinationInfoHolder(destination, samlMessage, relayState);

    PostBindingUtil.sendPost(destinationHolder, response, willSendRequest);
  }

  /**
   * <p>
   * Initialize the KeyProvider configurations. This configurations are to be
   * used during signing and validation of SAML assertions.
   * </p>
   *
   * @param context Apache Catalina Context
   * @throws LifecycleException any exception occurred while processing key
   *           provider
   */
  protected void initKeyProvider(Context context) throws LifecycleException {
    if (!doSupportSignature()) {
      return;
    }

    KeyProviderType keyProvider = this.spConfiguration.getKeyProvider();

    if (keyProvider == null && doSupportSignature())
      throw new LifecycleException(ErrorCodes.NULL_VALUE + "KeyProvider is null for context=" + context.getName());

    try {
      String keyManagerClassName = keyProvider.getClassName();
      if (keyManagerClassName == null)
        throw new RuntimeException(ErrorCodes.NULL_VALUE + "KeyManager class name");

      Class<?> clazz = SecurityActions.loadClass(getClass(), keyManagerClassName);

      if (clazz == null)
        throw new ClassNotFoundException(ErrorCodes.CLASS_NOT_LOADED + keyManagerClassName);
      this.keyManager = (TrustKeyManager) clazz.newInstance();

      List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);

      keyManager.setAuthProperties(authProperties);
      keyManager.setValidatingAlias(keyProvider.getValidatingAlias());

      String identityURL = this.spConfiguration.getIdentityURL();

      // Special case when you need X509Data in SignedInfo
      if (authProperties != null) {
        for (AuthPropertyType authPropertyType : authProperties) {
          String key = authPropertyType.getKey();
          if (GeneralConstants.X509CERTIFICATE.equals(key)) {
            // we need X509Certificate in SignedInfo. The value is the alias
            // name
            keyManager.addAdditionalOption(GeneralConstants.X509CERTIFICATE, authPropertyType.getValue());
            break;
          }
        }
      }
      keyManager.addAdditionalOption(ServiceProviderBaseProcessor.IDP_KEY, new URL(identityURL).getHost());
    } catch (Exception e) {
      logger.trustKeyManagerCreationError(e);
      throw new LifecycleException(e.getLocalizedMessage());
    }

    logger.trace("Key Provider=" + keyProvider.getClassName());
  }

  @Override
  protected boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {
    if (response instanceof Response) {
      LoginConfig loginConfig = request.getContext().getLoginConfig();
      Response catalinaResponse = (Response) response;
      return authenticate(request, catalinaResponse, loginConfig);
    }
    throw logger.samlSPResponseNotCatalinaResponseError(response);
  }

  /**
   * Authenticate the request
   *
   * @param request Apache Catalina Request
   * @param response Apache Catalina Response
   * @return true if authenticated, else false
   * @throws IOException any I/O exception
   */
  public boolean authenticate(Request request, HttpServletResponse response) throws IOException {
    if (response instanceof Response) {
      LoginConfig loginConfig = request.getContext().getLoginConfig();
      Response catalinaResponse = (Response) response;
      return authenticate(request, catalinaResponse, loginConfig);
    }
    throw logger.samlSPResponseNotCatalinaResponseError(response);
  }

  /*
   * (non-Javadoc)
   * @see
   * org.apache.catalina.authenticator.FormAuthenticator#authenticate(org.apache
   * .catalina.connector.Request, org.apache.catalina.connector.Response,
   * org.apache.catalina.deploy.LoginConfig)
   */
  private boolean authenticate(Request request, Response response, LoginConfig loginConfig) throws IOException {
    try {
      // needs to be done first, *before* accessing any parameters.
      // super.authenticate(..) gets called to late
      String characterEncoding = getCharacterEncoding();
      if (characterEncoding != null) {
        request.setCharacterEncoding(characterEncoding);
      }

      Session session = request.getSessionInternal(true);

      // check if this call is resulting from the redirect after successful
      // authentication.
      // if so, make the authentication successful and continue the original
      // request
      if (saveRestoreRequest && matchRequest(request)) {
        logger.trace("Restoring request from session '" + session.getIdInternal() + "'");
        Principal savedPrincipal = (Principal) session.getNote(FORM_PRINCIPAL_NOTE);
        register(request,
                 response,
                 savedPrincipal,
                 HttpServletRequest.FORM_AUTH,
                 (String) session.getNote(Constants.SESS_USERNAME_NOTE),
                 (String) session.getNote(Constants.SESS_PASSWORD_NOTE));

        // try to restore the original request (including post data, etc...)
        if (restoreRequest(request, session)) {
          // success! user is authenticated; continue processing original
          // request
          logger.trace("Continuing with restored request.");
          return true;
        } else {
          // no saved request found...
          logger.trace("Restore of original request failed!");
          response.sendError(HttpServletResponse.SC_BAD_REQUEST);
          return false;
        }
      }

      // Eagerly look for Local LogOut
      boolean localLogout = isLocalLogout(request);

      if (localLogout) {
        try {
          sendToLogoutPage(request, response, session);
        } catch (ServletException e) {
          logger.samlLogoutError(e);
          throw new IOException(e);
        }
        return false;
      }

      String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
      String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

      Principal principal = request.getUserPrincipal();

      // If we have already authenticated the user and there is no request from
      // IDP or logout from user
      if (principal != null && !(isGlobalLogout(request) || isNotNull(samlRequest) || isNotNull(samlResponse)))
        return true;

      // General User Request
      if (!isNotNull(samlRequest) && !isNotNull(samlResponse)) {
        return generalUserRequest(request, response, loginConfig);
      }

      // Handle a SAML Response from IDP
      if (isNotNull(samlResponse)) {
        return handleSAMLResponse(request, response, loginConfig);
      }

      // Handle SAML Requests from IDP
      if (isNotNull(samlRequest)) {
        return handleSAMLRequest(request, response, loginConfig);
      } // end if

      return localAuthentication(request, response, loginConfig);
    } catch (IOException e) {
      if (StringUtil.isNotNull(spConfiguration.getErrorPage())) {
        try {
          request.getRequestDispatcher(spConfiguration.getErrorPage()).forward(request.getRequest(), response);
        } catch (ServletException e1) {
          logger.samlErrorPageForwardError(spConfiguration.getErrorPage(), e1);
        }
        return false;
      } else {
        throw e;
      }
    }
  }

  /**
   * <p>
   * Indicates if the current request is a GlobalLogout request.
   * </p>
   *
   * @param request Apache Catalina Request
   * @return true if this is a global SAML logout
   */
  private boolean isGlobalLogout(Request request) {
    String gloStr = request.getParameter(GeneralConstants.GLOBAL_LOGOUT);
    return isNotNull(gloStr) && "true".equalsIgnoreCase(gloStr);
  }

  /**
   * <p>
   * Indicates if the current request is a LocalLogout request.
   * </p>
   *
   * @param request Apache Catalina Request
   * @return true if this is a local SAML logout
   */
  private boolean isLocalLogout(Request request) {
    try {
      if (request.getCharacterEncoding() == null) {
        request.setCharacterEncoding("UTF-8");
      }
    } catch (UnsupportedEncodingException e) {
      logger.error("Request have no encoding, and we are unable to set it to UTF-8");
      logger.error(e);
    }
    String lloStr = request.getParameter(GeneralConstants.LOCAL_LOGOUT);
    return isNotNull(lloStr) && "true".equalsIgnoreCase(lloStr);
  }

  /**
   * Handle the IDP Request
   *
   * @param request Apache Catalina Request
   * @param response Apache Catalina Response
   * @param loginConfig Apache Catalina Login Config
   * @return true if processed by SAML Workflow
   * @throws IOException any I/O error while authenticating
   */
  private boolean handleSAMLRequest(Request request, Response response, LoginConfig loginConfig) throws IOException {
    String samlRequest = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
    HTTPContext httpContext = new HTTPContext(request, response, context.getServletContext());
    Set<SAML2Handler> handlers = chain.handlers();

    try {
      ServiceProviderSAMLRequestProcessor requestProcessor = new ServiceProviderSAMLRequestProcessor(
                                                                                                     request.getMethod()
                                                                                                            .equals("POST"),
                                                                                                     this.serviceURL,
                                                                                                     this.picketLinkConfiguration);
      requestProcessor.setTrustKeyManager(keyManager);
      boolean result = requestProcessor.process(samlRequest, httpContext, handlers, chainLock);

      if (enableAudit) {
        PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent("Info");
        auditEvent.setType(PicketLinkAuditEventType.REQUEST_FROM_IDP);
        auditEvent.setWhoIsAuditing(getContextPath());
        auditHelper.audit(auditEvent);
      }

      // If response is already commited, we need to stop with processing of
      // HTTP request
      if (response.isCommitted() || response.isAppCommitted())
        return false;

      if (result)
        return result;
    } catch (Exception e) {
      logger.samlSPHandleRequestError(e);
      throw logger.samlSPProcessingExceptionError(e);
    }

    return localAuthentication(request, response, loginConfig);
  }

  private Document toSAMLResponseDocument(String samlResponse, boolean isPostBinding) throws ParsingException {
    InputStream dataStream = null;

    if (isPostBinding) {
      // deal with SAML response from IDP
      dataStream = PostBindingUtil.base64DecodeAsStream(samlResponse);
    } else {
      // deal with SAML response from IDP
      dataStream = RedirectBindingUtil.base64DeflateDecode(samlResponse);
    }

    try {
      return DocumentUtil.getDocument(dataStream);
    } catch (Exception e) {
      logger.samlResponseFromIDPParsingFailed();
      throw new ParsingException("", e);
    }
  }

  /**
   * Handle IDP Response
   *
   * @param request Apache Catalina Request
   * @param response Apache Catalina Response
   * @param loginConfig Apache Catalina Login Config
   * @return true if logged in in SAML SP side
   * @throws IOException any I/O error in authentication process
   */
  private boolean handleSAMLResponse(Request request, Response response, LoginConfig loginConfig) throws IOException {
    if (!super.validate(request)) {
      throw new IOException(ErrorCodes.VALIDATION_CHECK_FAILED);
    }

    String samlVersion = getSAMLVersion(request);

    if (!JBossSAMLConstants.VERSION_2_0.get().equals(samlVersion)) {
      return handleSAML11UnsolicitedResponse(request, response, loginConfig, this);
    }

    return handleSAML2Response(request, response, loginConfig);
  }

  private boolean handleSAML2Response(Request request, Response response, LoginConfig loginConfig) throws IOException {
    Session session = request.getSessionInternal(true);
    String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);
    HTTPContext httpContext = new HTTPContext(request, response, context.getServletContext());
    Set<SAML2Handler> handlers = chain.handlers();

    Principal principal = request.getUserPrincipal();

    boolean willSendRequest;// deal with SAML response from IDP

    try {
      ServiceProviderSAMLResponseProcessor responseProcessor =
                                                             new ServiceProviderSAMLResponseProcessor(request.getMethod()
                                                                                                             .equals("POST"),
                                                                                                      serviceURL,
                                                                                                      this.picketLinkConfiguration);
      if (auditHelper != null) {
        responseProcessor.setAuditHelper(auditHelper);
      }

      responseProcessor.setTrustKeyManager(keyManager);

      SAML2HandlerResponse saml2HandlerResponse = responseProcessor.process(samlResponse,
                                                                            httpContext,
                                                                            handlers,
                                                                            chainLock);

      Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
      String relayState = saml2HandlerResponse.getRelayState();

      String destination = saml2HandlerResponse.getDestination();

      willSendRequest = saml2HandlerResponse.getSendRequest();

      String destinationQueryStringWithSignature = saml2HandlerResponse.getDestinationQueryStringWithSignature();

      if (destination != null && samlResponseDocument != null) {
        sendRequestToIDP(destination,
                         samlResponseDocument,
                         relayState,
                         request,
                         response,
                         willSendRequest,
                         destinationQueryStringWithSignature);
      } else {
        // See if the session has been invalidated

        boolean sessionValidity = session.isValid();

        if (!sessionValidity) {
          sendToLogoutPage(request, response, session);
          return false;
        }

        // We got a response with the principal
        List<String> roles = saml2HandlerResponse.getRoles();

        if (principal == null) {
          principal = (Principal) session.getSession().getAttribute(GeneralConstants.PRINCIPAL_ID);
        }

        String username = principal.getName();
        String password = ServiceProviderSAMLContext.EMPTY_PASSWORD;

        username = checkForEmail(username);

        roles.addAll(extractGateinRoles(username));
        if (logger.isTraceEnabled()) {
          logger.trace("Roles determined for username=" + username + "=" + Arrays.toString(roles.toArray()));
        }

        // Map to JBoss specific principal
        if ((new ServerDetector()).isJboss() || jbossEnv) {
          // Push a context
          ServiceProviderSAMLContext.push(username, roles);
          principal = context.getRealm().authenticate(username, password);
          ServiceProviderSAMLContext.clear();
        } else {
          // tomcat env
          principal = getGenericPrincipal(request, username, roles);
        }

        session.setNote(Constants.SESS_USERNAME_NOTE, username);
        session.setNote(Constants.SESS_PASSWORD_NOTE, password);
        request.setUserPrincipal(principal);

        if (enableAudit) {
          PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent("Info");
          auditEvent.setType(PicketLinkAuditEventType.RESPONSE_FROM_IDP);
          auditEvent.setSubjectName(username);
          auditEvent.setWhoIsAuditing(getContextPath());
          auditHelper.audit(auditEvent);
        }

        // Redirect the user to the originally requested URL
        if (saveRestoreRequest) {
          // Store the authenticated principal in the session.
          session.setNote(FORM_PRINCIPAL_NOTE, principal);

          // Redirect to the original URL. Note that this will trigger the
          // authenticator again, but on resubmission we will look in the
          // session notes to retrieve the authenticated principal and
          // prevent reauthentication
          String requestURI = savedRequestURL(session);

          if (requestURI != null) {
            logger.trace("Redirecting back to original Request URI: " + requestURI);
            response.sendRedirect(response.encodeRedirectURL(requestURI));
          }
        }

        register(request, response, principal, HttpServletRequest.FORM_AUTH, username, password);
        return true;
      }
    } catch (ProcessingException pe) {
      Throwable t = pe.getCause();
      if (t != null && t instanceof AssertionExpiredException) {
        logger.error("Assertion has expired. Asking IDP for reissue");
        if (enableAudit) {
          PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent("Info");
          auditEvent.setType(PicketLinkAuditEventType.EXPIRED_ASSERTION);
          auditEvent.setAssertionID(((AssertionExpiredException) t).getId());
          auditHelper.audit(auditEvent);
        }
        // Just issue a fresh request back to IDP
        return generalUserRequest(request, response, loginConfig);
      }
      logger.samlSPHandleRequestError(pe);
      throw logger.samlSPProcessingExceptionError(pe);
    } catch (Exception e) {
      logger.samlSPHandleRequestError(e);
      throw logger.samlSPProcessingExceptionError(e);
    }

    return localAuthentication(request, response, loginConfig);
  }



  private String getSAMLVersion(Request request) {
    String samlResponse = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);
    String version;

    try {
      Document samlDocument = toSAMLResponseDocument(samlResponse, "POST".equalsIgnoreCase(request.getMethod()));
      Element element = samlDocument.getDocumentElement();

      // let's try SAML 2.0 Version attribute first
      version = element.getAttribute("Version");

      if (isNullOrEmpty(version)) {
        // fallback to SAML 1.1 Minor and Major attributes
        String minorVersion = element.getAttribute("MinorVersion");
        String majorVersion = element.getAttribute("MajorVersion");

        version = minorVersion + "." + majorVersion;
      }
    } catch (Exception e) {
      throw new RuntimeException("Could not extract version from SAML Response.", e);
    }

    return version;
  }

  protected boolean isPOSTBindingResponse() {
    return spConfiguration.isIdpUsesPostBinding();
  }

  /*
   * (non-Javadoc)
   * @see
   * org.picketlink.identity.federation.bindings.tomcat.sp.BaseFormAuthenticator
   * #getBinding()
   */
  @Override
  protected String getBinding() {
    return spConfiguration.getBindingType();
  }

  /**
   * Handle the user invocation for the first time
   *
   * @param request Apache Catalina Request
   * @param response Apache Catalina Response
   * @param loginConfig Apache Catalina Login Config
   * @return true if logged in in SAML SP side
   * @throws IOException any I/O error in authentication process
   */
  private boolean generalUserRequest(Request request, Response response, LoginConfig loginConfig) throws IOException {
    Session session = request.getSessionInternal(true);
    boolean willSendRequest = false;
    HTTPContext httpContext = new HTTPContext(request, response, context.getServletContext());
    Set<SAML2Handler> handlers = chain.handlers();

    boolean postBinding = spConfiguration.getBindingType().equals("POST");

    // Neither saml request nor response from IDP
    // So this is a user request
    SAML2HandlerResponse saml2HandlerResponse = null;
    try {
      ServiceProviderBaseProcessor baseProcessor = new ServiceProviderBaseProcessor(postBinding,
                                                                                    serviceURL,
                                                                                    this.picketLinkConfiguration);
      if (issuerID != null)
        baseProcessor.setIssuer(issuerID);

      // If the user has a different desired idp
      String idp = (String) request.getAttribute(org.picketlink.identity.federation.web.constants.GeneralConstants.DESIRED_IDP);
      if (StringUtil.isNotNull(idp)) {
        baseProcessor.setIdentityURL(idp);
      } else {
        baseProcessor.setIdentityURL(identityURL);
      }
      baseProcessor.setAuditHelper(auditHelper);

      saml2HandlerResponse = baseProcessor.process(httpContext, handlers, chainLock);
    } catch (ProcessingException pe) {
      logger.samlSPHandleRequestError(pe);
      throw new RuntimeException(pe);
    } catch (ParsingException pe) {
      logger.samlSPHandleRequestError(pe);
      throw new RuntimeException(pe);
    } catch (ConfigurationException pe) {
      logger.samlSPHandleRequestError(pe);
      throw new RuntimeException(pe);
    }

    willSendRequest = saml2HandlerResponse.getSendRequest();

    Document samlResponseDocument = saml2HandlerResponse.getResultingDocument();
    String relayState = saml2HandlerResponse.getRelayState();

    String destination = saml2HandlerResponse.getDestination();
    String destinationQueryStringWithSignature = saml2HandlerResponse.getDestinationQueryStringWithSignature();

    if (destination != null && samlResponseDocument != null) {
      try {
        if (saveRestoreRequest && !isGlobalLogout(request)) {
          this.saveRequest(request, session);
        }
        if (enableAudit) {
          PicketLinkAuditEvent auditEvent = new PicketLinkAuditEvent("Info");
          auditEvent.setType(PicketLinkAuditEventType.REQUEST_TO_IDP);
          auditEvent.setWhoIsAuditing(getContextPath());
          auditHelper.audit(auditEvent);
        }
        sendRequestToIDP(destination,
                         samlResponseDocument,
                         relayState,
                         request,
                         response,
                         willSendRequest,
                         destinationQueryStringWithSignature);
        return false;
      } catch (Exception e) {
        logger.samlSPHandleRequestError(e);
        throw logger.samlSPProcessingExceptionError(e);
      }
    }

    return localAuthentication(request, response, loginConfig);
  }

  /**
   * Extract Gatein roles to put in Principal
   * 
   * @param userId
   * @return
   */
  private List<String> extractGateinRoles(String userId) {
    OrganizationService organizationService =
                                            PortalContainer.getInstance().getComponentInstanceOfType(OrganizationService.class);
    RolesExtractor rolesExtractor = PortalContainer.getInstance().getComponentInstanceOfType(RolesExtractor.class);
    List<String> result = new ArrayList<>();
    Set<MembershipEntry> entries = new MembershipHashSet();
    Collection<Membership> memberships;
    try {
      memberships = organizationService.getMembershipHandler().findMembershipsByUser(userId);
    } catch (Exception e) {
      memberships = null;
    }
    if (memberships != null) {
      for (Membership membership : memberships)
        entries.add(new MembershipEntry(membership.getGroupId(), membership.getMembershipType()));
    }
    result.addAll(rolesExtractor.extractRoles(userId, entries));
    return result;
  }

  /**
   * <p>
   * Indicates if the SP is configure with HTTP POST Binding.
   * </p>
   *
   * @return true if post binding
   */
  protected boolean isHttpPostBinding() {
    return getBinding().equalsIgnoreCase("POST");
  }

  public Context getContext() {
    return (Context) getContainer();
  }

  @Override
  public boolean restoreRequest(Request request, Session session) throws IOException {
    return super.restoreRequest(request, session);
  }

  /**
   * Subclasses need to return the context path based on the capability of their
   * servlet api
   * 
   * @return Servlet Context Path
   */
  protected abstract String getContextPath();

  protected Principal getGenericPrincipal(Request request, String username, List<String> roles) {
    // sometimes, IDP send username in assertion with capitals letters, or with
    // inconsistent format.
    // this option allows to force the username in lower case, just before
    // creating the principal,
    // so that, all operations in exo side will use a consistant format.
    String forceLowerCase = System.getProperty("gatein.sso.saml.username.forcelowercase", "false");
    if (forceLowerCase.equalsIgnoreCase("true")) {
      username = username.toLowerCase();
    }
    return new GenericPrincipal(username, null, roles);
  }

  private boolean isAjaxRequest(Request request) {
    String requestedWithHeader = request.getHeader(GeneralConstants.HTTP_HEADER_X_REQUESTED_WITH);
    return requestedWithHeader != null && "XMLHttpRequest".equalsIgnoreCase(requestedWithHeader);
  }

  private String checkForEmail(String username) {
    //allow to use email as identifier in SAML assertion
    //if username is an email, we read the related user, and return his username, if there is only one result with this email
    try {
      if (username.contains("@")) {
        OrganizationService organizationService = PortalContainer.getInstance().getComponentInstanceOfType(OrganizationService.class);
        UserHandler userHandler = organizationService.getUserHandler();
        Query emailQuery = new Query();
        emailQuery.setEmail(username);
        ListAccess<User> users;
        users = userHandler.findUsersByQuery(emailQuery);
        if (users != null && users.getSize() == 1) {
          return users.load(0, 1)[0].getUserName();
        }
      }
    } catch (Exception e) {
      logger.samlSPHandleRequestError(e);
      return null;
    }
    return username;
  }

}
