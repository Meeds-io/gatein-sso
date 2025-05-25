/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2025 Meeds Association contact@meeds.io
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
package org.picketlink.identity.federation.bindings.tomcat;

import java.io.IOException;
import java.security.Principal;
import java.util.StringTokenizer;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JBAS-2283: Provide custom header based authentication support
 *
 * Header Authenticator that deals with userid from the request header Requires two attributes configured on the Tomcat Service
 * - one for the http header denoting the authenticated identity and the other is the SESSION cookie
 *
 */
public abstract class AbstractGenericHeaderAuthenticator extends FormAuthenticator {

    protected static final PicketLinkLogger log = PicketLinkLoggerFactory.getLogger();

    // JBAS-4804: AbstractGenericHeaderAuthenticator injection of ssoid and sessioncookie name.
    private String httpHeaderForSSOAuth = null;

    private String sessionCookieForSSOAuth = null;

    /**
     * <p>
     * Obtain the value of the <code>httpHeaderForSSOAuth</code> attribute. This attribute is used to indicate the request
     * header ids that have to be checked in order to retrieve the SSO identity set by a third party security system.
     * </p>
     *
     * @return a <code>String</code> containing the value of the <code>httpHeaderForSSOAuth</code> attribute.
     */
    public String getHttpHeaderForSSOAuth() {
        return httpHeaderForSSOAuth;
    }

    /**
     * <p>
     * Set the value of the <code>httpHeaderForSSOAuth</code> attribute. This attribute is used to indicate the request header
     * ids that have to be checked in order to retrieve the SSO identity set by a third party security system.
     * </p>
     *
     * @param httpHeaderForSSOAuth a <code>String</code> containing the value of the <code>httpHeaderForSSOAuth</code>
     *        attribute.
     */
    public void setHttpHeaderForSSOAuth(String httpHeaderForSSOAuth) {
        this.httpHeaderForSSOAuth = httpHeaderForSSOAuth;
    }

    /**
     * <p>
     * Obtain the value of the <code>sessionCookieForSSOAuth</code> attribute. This attribute is used to indicate the names of
     * the SSO cookies that may be present in the request object.
     * </p>
     *
     * @return a <code>String</code> containing the names (separated by a <code>','</code>) of the SSO cookies that may have
     *         been set by a third party security system in the request.
     */
    public String getSessionCookieForSSOAuth() {
        return sessionCookieForSSOAuth;
    }

    /**
     * <p>
     * Set the value of the <code>sessionCookieForSSOAuth</code> attribute. This attribute is used to indicate the names of the
     * SSO cookies that may be present in the request object.
     * </p>
     *
     * @param sessionCookieForSSOAuth a <code>String</code> containing the names (separated by a <code>','</code>) of the SSO
     *        cookies that may have been set by a third party security system in the request.
     */
    public void setSessionCookieForSSOAuth(String sessionCookieForSSOAuth) {
        this.sessionCookieForSSOAuth = sessionCookieForSSOAuth;
    }

    /**
     * <p>
     * Creates an instance of <code>AbstractGenericHeaderAuthenticator</code>.
     * </p>
     */
    public AbstractGenericHeaderAuthenticator() {
        super();
    }

    public boolean performAuthentication(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        boolean trace = log.isTraceEnabled();
        if (log.isTraceEnabled()) {
            log.trace("Authenticating user");
        }

        Principal principal = request.getUserPrincipal();
        if (principal != null) {
            if (trace)
                log.trace("Already authenticated '" + principal.getName() + "'");
            return true;
        }

        Realm realm = context.getRealm();
        Session session = request.getSessionInternal(true);

        String username = getUserId(request);
        String password = getSessionCookie(request);

        // Check if there is sso id as well as sessionkey
        if (username == null || password == null) {
            if (log.isTraceEnabled()) {
                log.trace("Username is null or password(sessionkey) is null:fallback to form auth");
            }
            return super.authenticate(request, response);
        }
        principal = realm.authenticate(username, password);

        if (principal == null) {
            forwardToErrorPage(request, response, config);
            return false;
        }

        session.setNote(Constants.SESS_USERNAME_NOTE, username);
        session.setNote(Constants.SESS_PASSWORD_NOTE, password);
        request.setUserPrincipal(principal);

        register(request, response, principal, HttpServletRequest.FORM_AUTH, username, password);
        return true;
    }

    /**
     * Get the username from the request header
     *
     * @param request
     * @return
     */
    protected String getUserId(Request request) {
        String ssoid = null;
        // We can have a comma-separated ids
        String ids = this.httpHeaderForSSOAuth;

        if (ids == null || ids.length() == 0)
            throw new IllegalStateException("Http headers configuration in tomcat service missing");

        StringTokenizer st = new StringTokenizer(ids, ",");
        while (st.hasMoreTokens()) {
            ssoid = request.getHeader(st.nextToken());
            if (ssoid != null)
                break;
        }
        if (log.isTraceEnabled()) {
            log.trace("SSOID-" + ssoid);
        }
        return ssoid;
    }

    /**
     * Obtain the session cookie from the request
     *
     * @param request
     * @return
     */
    protected String getSessionCookie(Request request) {
        Cookie[] cookies = request.getCookies();
        log.trace("Cookies:" + cookies);
        int numCookies = cookies != null ? cookies.length : 0;

        // We can have comma-separated ids
        String ids = sessionCookieForSSOAuth;

        if (ids == null || ids.length() == 0)
            throw new IllegalStateException("Session cookies configuration in tomcat service missing");

        StringTokenizer st = new StringTokenizer(ids, ",");
        while (st.hasMoreTokens()) {
            String cookieToken = st.nextToken();
            String val = getCookieValue(cookies, numCookies, cookieToken);
            if (val != null)
                return val;
        }
        if (log.isTraceEnabled()) {
            log.trace("Session Cookie not found");
        }
        return null;
    }

    /**
     * Get the value of a cookie if the name matches the token
     *
     * @param cookies array of cookies
     * @param numCookies number of cookies in the array
     * @param token Key
     * @return value of cookie
     */
    protected String getCookieValue(Cookie[] cookies, int numCookies, String token) {
        for (int i = 0; i < numCookies; i++) {
            Cookie cookie = cookies[i];
            log.trace("Matching cookieToken:" + token + " with cookie name=" + cookie.getName());
            if (token.equals(cookie.getName())) {
                if (log.isTraceEnabled()) {
                    log.trace("Cookie-" + token + " value=" + cookie.getValue());
                }
                return cookie.getValue();
            }
        }
        return null;
    }
}
