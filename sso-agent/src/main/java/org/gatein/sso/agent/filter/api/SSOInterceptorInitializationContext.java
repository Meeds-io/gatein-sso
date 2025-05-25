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
package org.gatein.sso.agent.filter.api;


import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;

import jakarta.servlet.FilterConfig;

/**
 * Context, which encapsulates all initialization configuration about {@link SSOInterceptor} and is able to recognize
 * whether interceptor was initialized through exo kernel or through Servlet API (old way)
 *
 */
public class SSOInterceptorInitializationContext
{
   private final FilterConfig filterConfig;
   private final InitParams initParams;
   private final ExoContainerContext containerContext;
   private final String containerName;

   // If true, interceptor was initialized through Servlet API. If false, interceptor was initialized through exo kernel.
   private final boolean initializedFromServletAPI;


   public SSOInterceptorInitializationContext(FilterConfig filterConfig, InitParams initParams, ExoContainerContext containerContext)
   {
      this.filterConfig = filterConfig;
      this.initParams = initParams;
      this.containerContext = containerContext;
      this.containerName = containerContext == null ? null : containerContext.getName();
      this.initializedFromServletAPI = filterConfig != null;
   }

   public String getInitParameter(String paramName)
   {
      if (initParams != null)
      {
         ValueParam param = initParams.getValueParam(paramName);
         return param==null ? null : substitutePortalContainerName(param.getValue());
      }

      return filterConfig.getInitParameter(paramName);
   }

   /**
    * Substitus portal container string @@portal.container.name@@ with portal container name
    * Example: For input like aaa_@@portal.container.name@@_bbb returns something like "aaa_portal_bbb"
    *
    * @param input
    * @return substituted string
    */
   private String substitutePortalContainerName(String input)
   {
      return input.replaceAll(AbstractSSOInterceptor.PORTAL_CONTAINER_SUBSTITUTION_PATTERN, this.containerName);
   }

   public boolean isInitializedFromServletAPI()
   {
      return initializedFromServletAPI;
   }

   public ExoContainer getExoContainer()
   {
      return containerContext.getContainer();
   }

   public String toString()
   {
      return "SSOInterceptorInitializationContext filterConfig=" + filterConfig
            + ", initParams: " + initParams
            + ", initializedFromServletAPI: " + initializedFromServletAPI
            + ", containerName: " + containerName;
   }
}
