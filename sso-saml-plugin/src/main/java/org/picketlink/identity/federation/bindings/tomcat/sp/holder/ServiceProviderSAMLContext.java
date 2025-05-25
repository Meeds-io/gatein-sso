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
package org.picketlink.identity.federation.bindings.tomcat.sp.holder;

import org.picketlink.identity.federation.core.constants.PicketLinkFederationConstants;

import java.util.List;

/**
 * A context of username/roles to be used by login modules
 *
 */
public class ServiceProviderSAMLContext {
    public static final String EMPTY_PASSWORD = "EMPTY_STR";

    private static ThreadLocal<String> username = new ThreadLocal<String>();
    private static ThreadLocal<List<String>> userRoles = new ThreadLocal<List<String>>();

    public static void push(String user, List<String> roles) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkFederationConstants.RUNTIME_PERMISSION_CORE);
        }
        username.set(user);
        userRoles.set(roles);
    }

    public static void clear() {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(PicketLinkFederationConstants.RUNTIME_PERMISSION_CORE);
        }
        username.remove();
        userRoles.remove();
    }

    public static String getUserName() {
        return username.get();
    }

    public static List<String> getRoles() {
        return userRoles.get();
    }
}