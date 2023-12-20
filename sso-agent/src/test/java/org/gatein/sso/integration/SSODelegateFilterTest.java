package org.gatein.sso.integration;

import junit.framework.TestCase;

public class SSODelegateFilterTest extends TestCase
{
  public void testIsMappedTo() {
    SSODelegateFilter ssoDelegateFilter = new SSODelegateFilter();
    assertTrue(ssoDelegateFilter.isMappedTo("/*", "/"));
    assertTrue(ssoDelegateFilter.isMappedTo(".*", "/"));
    assertTrue(ssoDelegateFilter.isMappedTo("/sso", "/sso"));
    assertFalse(ssoDelegateFilter.isMappedTo("/sso", "/samlsso"));
    assertTrue(ssoDelegateFilter.isMappedTo("/.*sso", "/samlsso"));
    assertTrue(ssoDelegateFilter.isMappedTo("/.*sso", "/samlsso"));
    assertFalse(ssoDelegateFilter.isMappedTo("/.*sso", "/ssosaml"));
  }
}
