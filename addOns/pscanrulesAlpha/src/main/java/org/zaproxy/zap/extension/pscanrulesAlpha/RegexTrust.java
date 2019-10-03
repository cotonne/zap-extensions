package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.regex.Pattern;

public class RegexTrust implements Trust {
  private final Pattern regex;

  public RegexTrust(String regex) {
    this.regex = Pattern.compile(regex);
  }

  @Override
  public boolean isTrusted(String url) {
    return regex.matcher(url).matches();
  }
}
