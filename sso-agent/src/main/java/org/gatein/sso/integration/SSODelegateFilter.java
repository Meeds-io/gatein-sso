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
package org.gatein.sso.integration;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.filter.api.SSOInterceptor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Filter will delegate to SSO interceptors
 *
 */
public class SSODelegateFilter extends AbstractFilter
{
   private volatile Map<SSOInterceptor, String> ssoInterceptors;

   private static final Log                    log = ExoLogger.getLogger(SSODelegateFilter.class);

   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      if (SSOUtils.isSSOEnabled())
      {
         SSOFilterChain ssoChain = new SSOFilterChain(chain, getInterceptors(), this);
         ssoChain.doFilter(request, response);
      }
      else
      {
         chain.doFilter(request, response);
      }
   }

   private Map<SSOInterceptor, String> getInterceptors()
   {
      if (ssoInterceptors == null)
      {
         synchronized (this)
         {
            if (ssoInterceptors == null)
            {
               SSOFilterIntegrator ssoFilterIntegrator = (SSOFilterIntegrator)getContainer().getComponentInstanceOfType(SSOFilterIntegrator.class);
               ssoInterceptors = ssoFilterIntegrator.getSSOInterceptors();
               log.info("Initialized SSO integrator with interceptors: " + ssoInterceptors);
            }
         }
      }

      return ssoInterceptors;
   }

   public void destroy()
   {
   }

   public static class SSOFilterChain implements FilterChain
   {

      private final FilterChain containerChain;
      private final Iterator<Map.Entry<SSOInterceptor, String>> iterator;
      private final SSODelegateFilter ssoDelegateFilter;

      public SSOFilterChain(FilterChain containerChain, Map<SSOInterceptor, String> interceptors, SSODelegateFilter ssoDelegateFilter)
      {
         this.containerChain = containerChain;
         this.iterator = interceptors.entrySet().iterator();
         this.ssoDelegateFilter = ssoDelegateFilter;
      }

      public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException
      {
         while (iterator.hasNext())
         {
            Map.Entry<SSOInterceptor, String> current = iterator.next();
            HttpServletRequest hRequest = (HttpServletRequest) request;
            if (log.isTraceEnabled())
            {
               log.trace("Trying mapping " + current.getValue() + " of SSO interceptor " + current.getKey()
                     + ". Request URI is " + hRequest.getRequestURI());
            }

            if (ssoDelegateFilter.isMappedTo(current.getValue(), hRequest.getServletPath()))
            {
               SSOInterceptor interceptor = current.getKey();
               if (log.isTraceEnabled())
               {
                  log.trace("Going to invoke SSO interceptor " + interceptor);
               }
               interceptor.doFilter(request, response, this);
               return;
            }
         }

         if (log.isTraceEnabled())
         {
            log.trace("No more SSO interceptors. Going to invoke container filter chain " + containerChain);
         }
         containerChain.doFilter(request, response);
         return;
      }
   }

   protected boolean isMappedTo(String filterMapping, String path)
   {
      if ("/*".equals(filterMapping))
      {
         return true;
      }
      else if (Pattern.compile(filterMapping).matcher(path).matches())
      {
         return true;
      }

      return false;
   }
}
