/*
 * This file is part of the Meeds project (https://meeds.io/).
 * Copyright (C) 2020 Meeds Association
 * contact@meeds.io
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.gatein.sso.saml.plugin.filter;

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

import org.gatein.sso.agent.filter.api.SSOInterceptorInitializationContext;

/**
 * This HTTP FilterConfig allows to inject some eXo Kernel Init Params
 * to Servlet Context Init Params
 */
public class SAMLFilterConfig implements FilterConfig {
  private String                              filterName;

  private ServletContext                      servletContext;

  private SSOInterceptorInitializationContext interceptorContext;

  public SAMLFilterConfig(String filterName,
                          ServletContext servletContext,
                          SSOInterceptorInitializationContext interceptorContext) {
    this.filterName = filterName;
    this.servletContext = servletContext;
    this.interceptorContext = interceptorContext;
  }

  @Override
  public ServletContext getServletContext() {
    return servletContext;
  }

  @Override
  public Enumeration<String> getInitParameterNames() {
    return null;
  }

  @Override
  public String getInitParameter(String name) {
    return interceptorContext.getInitParameter(name);
  }

  @Override
  public String getFilterName() {
    return filterName;
  }
}
