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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ServletAccess
{
   
   private static ThreadLocal<Holder> holderThreadLocal = new ThreadLocal<Holder>();

   public static void setRequestAndResponse(HttpServletRequest request, HttpServletResponse response)
   {
      holderThreadLocal.set(new Holder(request, response));
   }
   
   public static void resetRequestAndResponse()
   {
      holderThreadLocal.set(null);
   }
   
   public static HttpServletRequest getRequest()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletRequest;
      }

      return null;
   }

   public static HttpServletResponse getResponse()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletResponse;
      }

      return null;
   }
   
   private static class Holder
   {
      private final HttpServletRequest servletRequest;
      private final HttpServletResponse servletResponse;
      
      private Holder(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      {
         this.servletRequest = servletRequest;
         this.servletResponse = servletResponse;
      }
   }
}
