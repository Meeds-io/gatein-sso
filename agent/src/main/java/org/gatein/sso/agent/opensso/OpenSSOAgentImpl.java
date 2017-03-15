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
package org.gatein.sso.agent.opensso;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.GenericAgent;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class OpenSSOAgentImpl extends GenericAgent implements OpenSSOAgent
{
   // HttpSession attribute, which will be used to check that response message from CDC contains same ID of InResponseTo as the ID, which we used in OpenSSOCDLoginRedirectFilter
   public static final String IN_RESPONSE_TO_ATTR = "OpenSSOAgent.InResponseTo";

    // Possible line separators on various OS
    private static final String WINDOWS_SEPARATOR = "\r\n";
    private static final String UNIX_SEPARATOR = "\n";
    private static final String MAC_SEPARATOR = "\r";

    private static final String[] LINE_SEPARATORS = new String[] { WINDOWS_SEPARATOR, UNIX_SEPARATOR, MAC_SEPARATOR };

   private static Logger log = LoggerFactory.getLogger(OpenSSOAgentImpl.class);
	
	private String cookieName;
	private String serverUrl;
    private final String lineSeparator;

   private CDMessageParser cdcMessageParser = new CDMessageParser();

	public OpenSSOAgentImpl(InitParams params)
	{
        // TODO: Read serverUrl and cookieName from params
        if (params == null)
        {
            this.lineSeparator = null;
            return;
        }

        ValueParam lineSeparatorParam = params.getValueParam("lineSeparator");
        if (lineSeparatorParam != null)
        {
            this.lineSeparator = lineSeparatorParam.getValue();
        }
        else
        {
            this.lineSeparator = null;
        }

        log.debug("Agent configured with line separator: " + this.lineSeparator);
	}

   public void setCookieName(String cookieName)
   {
      this.cookieName = cookieName;
   }

   public void setServerUrl(String serverUrl)
   {
      this.serverUrl = serverUrl;
   }


		
	public void validateTicket(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws Exception
	{
      // Start with processing message from CDCServlet if this message is available (it should be in servlet request parameter "LARES")
      if (tryMessageFromCDC(httpRequest, httpResponse))
      {
         return;
      }

      // Now cookie should be set and we can continue with cookie processing
		String token = null;
		Cookie[] cookies = httpRequest.getCookies();
		if(cookies == null)
		{
         return;
		}
		
		for(Cookie cookie: cookies)
		{
			if(cookie.getName().equals(this.cookieName))
			{
				token = cookie.getValue();
				break;
			}
		}
		
		if(token == null)
		{
		    throwIllegalStateException("No SSO Tokens Found");
		}
						
		if(token != null)
		{
			boolean isValid = this.isTokenValid(token);
			
			if(!isValid)
			{
            throwIllegalStateException("OpenSSO Token is not valid!!");
			}
		
			String subject = this.getSubject(token);			
			if(subject != null)
			{
            this.saveSSOCredentials(subject, httpRequest);
			}
		}
	}

   /**
    * This method is useful only for Cross-Domain (CD) authentication scenario when GateIn and OpenSSO are in different DNS domains and they can't share cookie.
    *
    * It performs:
    * <ul>
    * <li>Parse and validate message from OpenSSO CDCServlet.</li>
    * <li>Use ssoToken from parsed message and establish OpenSSO cookie iPlanetDirectoryPro</li>
    * <li>Redirects to InitiateLoginFilter but with cookie established. So in next request, we can perform agent validation against OpenSSO server</li>
    * </ul>
    *
    * @param httpRequest
    * @param httpResponse
    * @return true if parameter LARES with message from CDC is present in HttpServletRequest
    * @throws IOException
    */
   protected boolean tryMessageFromCDC(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
   {
      String encodedCDCMessage = httpRequest.getParameter("LARES");

      if (encodedCDCMessage == null)
      {
         if (log.isTraceEnabled())
         {
            log.trace("Message from CDC not found in this HttpServletRequest");
         }
         return false;
      }

      CDMessageContext messageContext = cdcMessageParser.parseMessage(encodedCDCMessage);
      if (log.isTraceEnabled())
      {
         log.trace("Successfully parsed messageContext " + messageContext);
      }

      // Validate received messageContext
      validateCDMessageContext(httpRequest, messageContext);

      // Establish cookie with ssoToken
      String ssoToken = messageContext.getSsoToken();
      Cookie cookie = new Cookie(cookieName, "\"" + ssoToken + "\"");
      cookie.setPath(httpRequest.getContextPath());
      httpResponse.addCookie(cookie);
      if (log.isTraceEnabled())
      {
         log.trace("Cookie " + cookieName + " with value " + ssoToken + " added to HttpResponse");
      }

      // Redirect again this request to be processed by OpenSSOAgent. Now we have cookie established
      String urlToRedirect = httpResponse.encodeRedirectURL(httpRequest.getRequestURI());
      httpResponse.sendRedirect(urlToRedirect);

      return true;
   }


   /**
    * Validation of various criterias in {@link CDMessageContext}
    *
    * @param httpRequest
    * @param context
    */
   protected void validateCDMessageContext(HttpServletRequest httpRequest, CDMessageContext context)
   {
      // First validate if context contains success
      if (!context.getSuccess())
      {
         throwIllegalStateException("CDMessageContext contains success=false. Check SAML message from CDCServlet");
      }

      // Now validate inResponseTo
      Integer inResponseToFromCDC = context.getInResponseTo();
      Integer inResponseToFromSession = (Integer)httpRequest.getSession().getAttribute(IN_RESPONSE_TO_ATTR);
      if (inResponseToFromSession == null || inResponseToFromCDC == null || !inResponseToFromCDC.equals(inResponseToFromSession))
      {
         throwIllegalStateException("inResponseTo from CDC message is " + inResponseToFromCDC + ", inResponseTo from Http session is " + inResponseToFromSession + ". Both should have same value");
      }

      // TODO: validate dates notBefore and notOnOrAfter

      // Validate that token is present
      if (context.getSsoToken() == null)
      {
         throwIllegalStateException("No token found in CDMessageContext. Check SAML message from CDCServlet");
      }
   }

	//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
	protected boolean isTokenValid(String token) throws Exception
	{
      DefaultHttpClient client = new DefaultHttpClient();
      HttpPost post;
		try
		{			
			String url = this.serverUrl+"/identity/isTokenValid";
			post = new HttpPost(url);

         List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
         nameValuePairs.add(new BasicNameValuePair("tokenid", token));
         post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

         HttpResponse httpResponse = client.execute(post);
         int status = httpResponse.getStatusLine().getStatusCode();
         HttpEntity entity = httpResponse.getEntity();
         String response = entity == null ? null : EntityUtils.toString(entity);

			log.debug("Status of token validation: " + status);
			log.debug("Response from token validation: " + response);
			
			if(response.contains(Boolean.TRUE.toString()))
			{
				return true;
			}
			
			return false;
		}
		finally
		{
         client.getConnectionManager().shutdown();
		}
	}	
	
	protected String getSubject(String token) throws Exception
	{
      DefaultHttpClient client = new DefaultHttpClient();
      HttpPost post;
		try
		{	
			String uid = null;
			String url = this.serverUrl+"/identity/attributes";
			post = new HttpPost(url);

         List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>(2);
         nameValuePairs.add(new BasicNameValuePair("subjectid", token));
         nameValuePairs.add(new BasicNameValuePair("attributes_names", "uid"));
         post.setEntity(new UrlEncodedFormEntity(nameValuePairs));

         HttpResponse httpResponse =  client.execute(post);
         int status = httpResponse.getStatusLine().getStatusCode();
         HttpEntity entity = httpResponse.getEntity();
         String response = entity == null ? null : EntityUtils.toString(entity);

			log.debug("Status of get subject: " + status);
			log.debug(response);
			
			if(response != null)
			{
				Properties properties = this.loadAttributes(response);												
				uid = properties.getProperty("uid");
			}
			
			
			return uid;
		}
		finally
		{
         client.getConnectionManager().shutdown();
		}		
	}
	
	protected Properties loadAttributes(String response) throws Exception
	{
		InputStream is = null;
		try
		{
			Properties properties = new Properties();		
			
			String[] tokens = response.split(getLineSeparator(response));
			String name = null;
			for(String token: tokens)
			{
				if(token.startsWith("userdetails.attribute.name"))
				{
					name = token.substring(token.indexOf("=")+1);
				}
				else if(token.startsWith("userdetails.attribute.value"))
				{
					String value = token.substring(token.indexOf("=")+1);
					
					if(name != null)
					{						
						properties.setProperty(name, value);
					}
					
					//cleanup
					name = null;
				}
			}
			
			return properties;
		}
		finally
		{
			if(is != null)
			{
				is.close();
			}
		}
	}

    // Use configured line separator or try to "guess" it from LINE_SEPARATORS set
    private String getLineSeparator(String response)
    {
        if (this.lineSeparator != null)
        {
            return lineSeparator;
        }
        else
        {
            for (String current : LINE_SEPARATORS)
            {
                if (response.contains(current))
                {
                    return current;
                }
            }

            throw new IllegalArgumentException("Can't obtain line separator from response string: " + response);
        }
    }

   private void throwIllegalStateException(String message)
   {
      log.warn(message);
      IllegalStateException ise = new IllegalStateException(message);
      throw ise;
   }

}
