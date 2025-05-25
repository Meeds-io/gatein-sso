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

import org.exoplatform.container.component.ComponentPlugin;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.filter.api.SSOInterceptor;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Kernel component, which holds references to all configured {@link org.gatein.sso.agent.filter.api.SSOInterceptor}
 * instances
 *
 */
public class SSOFilterIntegratorImpl implements SSOFilterIntegrator
{
   // Key is filter (SSOInterceptor), value is filterMapping
   private final Map<SSOInterceptor, String> ssoInterceptors = new LinkedHashMap<SSOInterceptor, String>();

   private static final Log                 log             = ExoLogger.getLogger(SSOFilterIntegratorImpl.class);

   public void addPlugin(ComponentPlugin plugin)
   {
      if (plugin instanceof SSOFilterIntegratorPlugin)
      {
         SSOFilterIntegratorPlugin ssoPlugin = (SSOFilterIntegratorPlugin)plugin;

         if (!ssoPlugin.isEnabled())
         {
            return;
         }

         SSOInterceptor ssoInterceptor = ssoPlugin.getFilter();
         this.ssoInterceptors.put(ssoInterceptor, ssoPlugin.getFilterMapping());

         log.debug("Added new SSOInterceptor " + ssoInterceptor);
      }
   }

   public Map<SSOInterceptor, String> getSSOInterceptors()
   {
      return ssoInterceptors;
   }

}
