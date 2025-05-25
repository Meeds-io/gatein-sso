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
package org.gatein.sso.agent.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import jakarta.servlet.ServletException;
import java.io.IOException;

/**
 * Valve for adding {@link jakarta.servlet.http.HttpServletRequest} and {@link jakarta.servlet.http.HttpServletResponse} into threadLocal
 * so that it can be accessed from Login Modules during authentication.
 *
 */
public class ServletAccessValve extends ValveBase
{
  private static final Log log = ExoLogger.getLogger(ServletAccessValve.class);
   
   @Override
   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      ServletAccess.setRequestAndResponse(request, response);
      if (log.isTraceEnabled())
      {
         log.trace("Current HttpServletRequest and HttpServletResponse added to ThreadLocal.");
      }

      try
      {
         getNext().invoke(request, response);
      }
      finally
      {
         ServletAccess.resetRequestAndResponse();
         if (log.isTraceEnabled())
         {
            log.trace("Cleaning ThreadLocal");
         }
      }
   }

}
