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
package org.gatein.sso.saml.plugin;

import java.io.Serializable;
import java.security.Principal;

/**
 * Forked class because this plugin can be used on both JBoss or Tomcat and we want to be independent on AS.
 *
 */
public class SimplePrincipal implements Principal, Serializable
{
   private static final long serialVersionUID = 7701951188631723290L;
   private final String name;

   public SimplePrincipal(String name)
   {
      this.name = name;
   }

   /**
    * Compare this SimplePrincipal's name against another Principal. If system property
    * org.jboss.security.simpleprincipal.equals.override is set to true will only
    * compare instances of SimplePrincipals.
    * @return true if name equals another.getName();
    */
   @Override
   public boolean equals(Object another)
   {
      String anotherName = ((Principal) another).getName();
      boolean equals = false;
      if (name == null)
         equals = anotherName == null;
      else
         equals = name.equals(anotherName);
      return equals;
   }

   @Override
   public int hashCode()
   {
      return (name == null ? 0 : name.hashCode());
   }

   @Override
   public String toString()
   {
      return name;
   }

   public String getName()
   {
      return name;
   }
}