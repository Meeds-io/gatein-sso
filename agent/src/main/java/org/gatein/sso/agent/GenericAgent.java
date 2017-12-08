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

package org.gatein.sso.agent;

import org.apache.commons.lang.StringUtils;
import org.exoplatform.commons.utils.ListAccess;
import org.exoplatform.commons.utils.PropertyManager;
import org.exoplatform.services.organization.Query;
import org.exoplatform.services.organization.User;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.wci.security.Credentials;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.services.organization.OrganizationService;

import javax.servlet.http.HttpServletRequest;

/**
 * Base agent superclass used by other SSO agents (CAS, JOSSO, OpenAM)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class GenericAgent
{
   private static Logger log = LoggerFactory.getLogger(GenericAgent.class);

   public static final String AUTHENTICATED_CREDENTIALS = "authenticatedCredentials";

   private static final String IS_CASE_INSENSITIVE = "exo.auth.case.insensitive";


   public void saveSSOCredentials(String username, HttpServletRequest httpRequest)
   {
      boolean case_insensitive_bool = true;
      String case_insensitive_str = PropertyManager.getProperty(IS_CASE_INSENSITIVE);
      if(case_insensitive_str != null) {
         case_insensitive_bool = Boolean.valueOf(case_insensitive_str);
      }
      if(case_insensitive_bool) {
         username = getUserPrincipal(username);
      }
      //Use empty password....it shouldn't be needed...this is a SSO login. The password has
      //already been presented with the SSO server. It should not be passed around for
      //better security
      Credentials credentials = new Credentials(username, "");

      httpRequest.getSession().setAttribute(Credentials.CREDENTIALS, credentials);

      // This is needed when using default login module stack instead of SSOLoginModule. In this case, GateIn authentication is done thanks to PortalLoginModule.
      httpRequest.getSession().setAttribute(GenericAgent.AUTHENTICATED_CREDENTIALS, credentials);

      log.debug("Credentials of user " + username + " saved into HTTP session.");
   }

   /**
    * @param username
    * @return gets the right username if the login input contains capital letters: EXOGTN-2267
    */
   public String getUserPrincipal(String username) {
      try {
         OrganizationService organizationService =
                 (OrganizationService) getContainer()
                         .getComponentInstance(OrganizationService.class);
         Query query = new Query();
         query.setUserName(username);
         ListAccess<User> users = organizationService.getUserHandler().findUsersByQuery(query);
         if (users.getSize() >= 1) {
            String loadedUsername  = "";
            User[] listusers = users.load(0, users.getSize());
            int found = 0;
            for(User user : listusers){
               if (username.equalsIgnoreCase(user.getUserName())) {
                  loadedUsername = user.getUserName();
                  found ++;
               }
            }
            if(found == 1 && StringUtils.isNotBlank(loadedUsername))
               username = loadedUsername;
            else
               log.warn("duplicate entry for user " + username);

         }
      } catch (Exception exception) {
         log.warn("Error while retrieving user " + username + " from IDM stores " , exception);
      }
      return username;
   }

   /**
    * @return Gives the {@link ExoContainer} that fits best with the current context
    */
   protected final ExoContainer getContainer()
   {
      ExoContainer container = ExoContainerContext.getCurrentContainer();
      if (container instanceof RootContainer) {
         container = PortalContainer.getInstance();
      }
      // The container is a PortalContainer or a StandaloneContainer
      return container;
   }

}