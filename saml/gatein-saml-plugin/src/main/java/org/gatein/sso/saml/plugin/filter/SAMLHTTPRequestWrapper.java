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
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This class is used to combine two HTTP Request datas
 */
public class SAMLHTTPRequestWrapper extends HttpServletRequestWrapper {
  private final HttpServletRequest originalHttpServletRequest;

  public SAMLHTTPRequestWrapper(HttpServletRequest request, HttpServletRequest originalHttpServletRequest) {
    super(request);
    this.originalHttpServletRequest = originalHttpServletRequest;
  }

  @Override
  public String getParameter(String name) {
    return originalHttpServletRequest.getParameter(name);
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    return originalHttpServletRequest.getParameterMap();
  }

  @Override
  public String[] getParameterValues(String name) {
    return originalHttpServletRequest.getParameterValues(name);
  }

  @Override
  public String getMethod() {
    return originalHttpServletRequest.getMethod();
  }

  @Override
  public String getHeader(String name) {
    return originalHttpServletRequest.getHeader(name);
  }

  @Override
  public Enumeration<String> getHeaders(String name) {
    return originalHttpServletRequest.getHeaders(name);
  }

  @Override
  public Enumeration<String> getHeaderNames() {
    return originalHttpServletRequest.getHeaderNames();
  }
}
