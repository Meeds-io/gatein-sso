package org.gatein.sso.saml.plugin.filter;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

/**
 * Used to avoid calling chain.doFilter in parent classes when needed
 * This will avoid duplicating source code to delete unnecessary code
 */
public class EmptyFilterChain implements FilterChain {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
    // Nothing to do
  }

}
