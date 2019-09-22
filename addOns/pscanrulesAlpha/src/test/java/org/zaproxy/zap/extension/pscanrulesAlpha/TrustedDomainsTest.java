package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.junit.Test;

import static org.junit.Assert.*;

public class TrustedDomainsTest {

    // Same domain: http://domain/.* http://domain/path
    // Port: http://domain/.* http://domain:80/path
    // Port: http://domain:80/.* http://domain/path
    // Domain: https://domain/.* https://domain/path
    // Sub-domain: http://.*\.domain/.* http://sub.domain/path
    // Sub-domain: http://.*\.domain/.* http://sub.domain/path


    @Test
    public void shouldBeIncludedForPath() {
        TrustedDomains trustedDomains = new TrustedDomains();
        trustedDomains.update("https://www.example2.com/.*");
        boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");
        assertTrue(included);
    }

    @Test
    public void shouldNotBeIncludedForDifferentDomain() {
        TrustedDomains trustedDomains = new TrustedDomains();
        trustedDomains.update("https://www.example2.com/.*");
        boolean included = trustedDomains.isIncluded("https://www.example3.com/page1");
        assertFalse(included);
    }

  @Test
  public void shouldNotBeIncludedForAnInvalidRegex() {
      TrustedDomains trustedDomains = new TrustedDomains();
      trustedDomains.update("[");
      boolean included = trustedDomains.isIncluded("https://www.example2.com/page1");
      assertFalse(included);
  }

    @Test
    public void shouldUpdateTrustedDomains() {
        TrustedDomains trustedDomains = new TrustedDomains();
        trustedDomains.update("https://www.example2.com/.*");
        trustedDomains.update("https://www.example3.com/.*");
        boolean included = trustedDomains.isIncluded("https://www.example3.com/page1");
        boolean notIncluded = trustedDomains.isIncluded("https://www.example3.com/page1");
        assertTrue(included);
        assertTrue(notIncluded);
    }
}
