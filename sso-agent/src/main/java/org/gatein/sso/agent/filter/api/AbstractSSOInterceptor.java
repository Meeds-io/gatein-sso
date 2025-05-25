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
import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;

/**
 * Base {@link SSOInterceptor} which adds possibility to be initialized either through Servlet API or through eXo kernel
 *
 */
public abstract class AbstractSSOInterceptor extends AbstractFilter implements SSOInterceptor
{
   public static final String PORTAL_CONTAINER_SUBSTITUTION_PATTERN = "@@portal.container.name@@";

   private SSOInterceptorInitializationContext interceptorContext;

   private static final Log                   log                                   =
                                                  ExoLogger.getLogger(AbstractSSOInterceptor.class);


   /**
    * Method is invoked if we are performing initialization through servlet api (web filter)
    */
   @Override
   protected final void afterInit(FilterConfig filterConfig) throws ServletException
   {
      this.interceptorContext = new SSOInterceptorInitializationContext(filterConfig, null, null);
      log.debug("Interceptor initialized with context " + interceptorContext);
      initImpl();
   }

   /**
    * Method is invoked if we are performing initialization through exo kernel
    */
   public final void initWithParams(InitParams params, ExoContainerContext containerContext)
   {
      this.interceptorContext = new SSOInterceptorInitializationContext(null, params, containerContext);
      log.debug("Interceptor initialized with context " + interceptorContext);
      initImpl();
   }

   /**
    * This method needs to be implemented by conrete filter. Filter should obtain it's init parameters by calling
    * {@link #getInitParameter(String)}. This works in both types of initialization
    * (Case1: Filter initialization through kernel, Case2: initialization through servlet API)
    */
   protected abstract void initImpl();

   /**
    * Read init parameter (works for both kernel initialization or Servlet API initialization)
    *
    * @param paramName parameter name
    * @return parameter value
    */
   public String getInitParameter(String paramName)
   {
      return interceptorContext.getInitParameter(paramName);
   }

   /**
    * Need to use different method name because method "super.getContainer()" is final :-/
    */
   protected ExoContainer getExoContainer()
   {
      if (interceptorContext.isInitializedFromServletAPI())
      {
         return super.getContainer();
      }
      else
      {
         return interceptorContext.getExoContainer();
      }
   }
}
