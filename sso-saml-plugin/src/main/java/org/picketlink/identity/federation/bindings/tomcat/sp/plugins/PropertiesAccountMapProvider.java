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
package org.picketlink.identity.federation.bindings.tomcat.sp.plugins;

import org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve;

import jakarta.servlet.ServletContext;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Implementation of
 * {@link org.picketlink.identity.federation.bindings.tomcat.sp.AbstractAccountChooserValve.AccountIDPMapProvider} using a
 * properties file
 *
 */
public class PropertiesAccountMapProvider implements AbstractAccountChooserValve.AccountIDPMapProvider {
    private ClassLoader classLoader = null;

    private ServletContext servletContext = null;

    public static final String PROP_FILE_NAME = "idpmap.properties";

    public static final String WEB_INF_PROP_FILE_NAME = "/WEB-INF/idpmap.properties";

    @Override
    public void setClassLoader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    public void setServletContext(ServletContext servletContext){
        this.servletContext = servletContext;
    }

    @Override
    public Map<String, String> getIDPMap() throws IOException {
        Map<String, String> idpmap = new HashMap<String, String>();

        InputStream inputStream = null;

        Properties properties = new Properties();
        if (classLoader != null) {
            inputStream = classLoader.getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream == null && servletContext != null) {
            inputStream = servletContext.getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream == null && servletContext != null) {
            inputStream = servletContext.getResourceAsStream(WEB_INF_PROP_FILE_NAME);
        }
        if(inputStream == null){
            inputStream = getClass().getResourceAsStream(PROP_FILE_NAME);
        }
        if (inputStream != null) {
            properties.load(inputStream);
            if (properties != null) {
                Set<Object> keyset = properties.keySet();
                for (Object key : keyset) {
                    idpmap.put((String) key, (String) properties.get(key));
                }
            }
        }
        return idpmap;
    }
}