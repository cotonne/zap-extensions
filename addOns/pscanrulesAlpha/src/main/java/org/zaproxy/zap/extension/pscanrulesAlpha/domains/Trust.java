package org.zaproxy.zap.extension.pscanrulesAlpha.domains;

public interface Trust {
    boolean isTrusted(String url);
}
