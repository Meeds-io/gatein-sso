package org.gatein.sso.saml.plugin.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

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
