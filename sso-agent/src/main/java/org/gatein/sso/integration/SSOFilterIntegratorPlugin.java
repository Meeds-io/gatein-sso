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

import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.component.BaseComponentPlugin;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.gatein.sso.agent.filter.api.SSOInterceptor;


/**
 * Kernel plugin for adding {@link SSOInterceptor} into chain
 *
 */
public class SSOFilterIntegratorPlugin extends BaseComponentPlugin {
   private final SSOInterceptor filter;
   private final boolean enabled;
   private final String filterMapping;

   private static final Log    log = ExoLogger.getLogger(SSOFilterIntegratorPlugin.class);

   public SSOFilterIntegratorPlugin(InitParams params, ExoContainerContext containerContext)
   {
      ValueParam filterClass = params.getValueParam("filterClass");
      ValueParam enabled = params.getValueParam("enabled");
      ValueParam filterMapping = params.getValueParam("filterMapping");
      if (filterClass == null || filterMapping == null)
      {
         throw new IllegalArgumentException("Parameters 'filterClass' and 'filterMapping' need to be provided");
      }

      this.enabled = enabled != null ? Boolean.parseBoolean(enabled.getValue()) : false;
      if (!isEnabled())
      {
         log.debug("Filter " + filterClass.getValue() + " disabled");
         this.filter = null;
         this.filterMapping = null;
         return;
      }

      this.filterMapping = filterMapping.getValue();
      String filterClazz = filterClass.getValue();
      log.debug("Plugin initialization with parameters filterClass: " + filterClazz + ", filterMapping: " + filterMapping);
      Class<SSOInterceptor> ssoInterceptorCl = (Class<SSOInterceptor>)SSOUtils.loadClass(filterClazz);
      try
      {
         this.filter = ssoInterceptorCl.newInstance();
      }
      catch (Exception e)
      {
         throw new RuntimeException("Can't instantiate " + ssoInterceptorCl, e);
      }

      this.filter.initWithParams(params, containerContext);
   }

   public boolean isEnabled()
   {
      return enabled;
   }

   public SSOInterceptor getFilter()
   {
      return filter;
   }

   public String getFilterMapping()
   {
      return filterMapping;
   }
}
