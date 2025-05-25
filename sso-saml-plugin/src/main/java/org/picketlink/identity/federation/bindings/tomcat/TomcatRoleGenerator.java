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
package org.picketlink.identity.federation.bindings.tomcat;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.apache.catalina.Role;
import org.apache.catalina.User;
import org.apache.catalina.realm.GenericPrincipal;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;

/**
 * Generate roles from Tomcat Principal
 *
 */
public class TomcatRoleGenerator implements RoleGenerator {
    
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    
    /**
     * @see RoleGenerator#generateRoles(Principal)
     * @throws IllegalArgumentException if principal is not of type GenericPrincipal or User
     */
    public List<String> generateRoles(Principal principal) {
        String className = principal.getClass().getCanonicalName();

        if (principal instanceof GenericPrincipal == false && principal instanceof User == false)
            throw logger.wrongTypeError("principal is not tomcat principal:" + className);
        List<String> userRoles = new ArrayList<String>();

        if (principal instanceof GenericPrincipal) {
            GenericPrincipal gp = (GenericPrincipal) principal;
            String[] roles = gp.getRoles();
            if (roles.length > 0)
                userRoles.addAll(Arrays.asList(roles));
        } else if (principal instanceof User) {
            User tomcatUser = (User) principal;
            Iterator<?> iter = tomcatUser.getRoles();
            while (iter.hasNext()) {
                Role tomcatRole = (Role) iter.next();
                userRoles.add(tomcatRole.getRolename());
            }
        }
        return userRoles;
    }
}