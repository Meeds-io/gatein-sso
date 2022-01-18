/*
* JBoss, a division of Red Hat
* Copyright 2006, Red Hat Middleware, LLC, and individual contributors as indicated
* by the @authors tag. See the copyright.txt in the distribution for a
* full listing of individual contributors.
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
package org.gatein.sso.agent.filter;

import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class LoginRedirectFilter extends AbstractSSOInterceptor
{
	String loginUrl;

  private static final Log log = ExoLogger.getLogger(LoginRedirectFilter.class);
	
	protected void initImpl()
	{
		this.loginUrl = getInitParameter("LOGIN_URL");
      log.info("Filter configuration: loginUrl=" + loginUrl);
	}
	
	public void destroy()
	{
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

      String urlToRedirect = getLoginRedirectURL(httpRequest);
      urlToRedirect = httpResponse.encodeRedirectURL(urlToRedirect);
      httpResponse.sendRedirect(urlToRedirect);
	}

   /**
    * @return value of parameter loginUrl. But can be overriden by subclasses.
    */
   protected String getLoginRedirectURL(HttpServletRequest httpRequest)
   {
      return this.loginUrl;
   }

}
