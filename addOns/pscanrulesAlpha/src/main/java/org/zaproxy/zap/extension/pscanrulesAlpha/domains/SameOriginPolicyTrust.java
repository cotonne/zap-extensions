package org.zaproxy.zap.extension.pscanrulesAlpha.domains;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.zaproxy.zap.extension.pscanrulesAlpha.domains.Trust;

public class SameOriginPolicyTrust implements Trust {
  private final URI origin;

  SameOriginPolicyTrust(URI origin) {
    this.origin = origin;
  }

  @Override
  public boolean isTrusted(String url) {
    try {
      URI resourceUri = new URI(url, false);
      return origin.getScheme().equals(resourceUri.getScheme())
          && origin.getAuthority().equals(resourceUri.getAuthority())
          && origin.getPort() == resourceUri.getPort();
    } catch (URIException e) {
      // Badly formatted resource should be ignored
      return true;
    }
  }
}
