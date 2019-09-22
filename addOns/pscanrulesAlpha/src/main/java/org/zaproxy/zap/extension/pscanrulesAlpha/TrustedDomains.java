package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class TrustedDomains {
    private static final Logger LOG = Logger.getLogger(TrustedDomains.class);

    // TODO Replace "rules.domains.trusted" with RuleConfigParam.RULE_DOMAINS_TRUSTED once
    // available.
    public static final String TRUSTED_DOMAINS_PROPERTY = "rules.domains.trusted";
    private String hashTrustedConfig = "";
    private List<String> trustedDomainRegexes = new ArrayList<>();

    public boolean check(String link) {
        // check the trusted domains
        for (String regex : this.trustedDomainRegexes) {
            try {
                if (link.matches(regex)) {
                    return false;
                }
            } catch (Exception e) {
                LOG.warn("Invalid regex in rule " + TRUSTED_DOMAINS_PROPERTY + ": " + regex, e);
            }
        }
        return true;
    }

    void checkIgnoreList(String trustedConf) {
        // TODO use hashCode?
        if (!trustedConf.equals(this.hashTrustedConfig)) {
            // Its changed
            trustedDomainRegexes.clear();
            this.hashTrustedConfig = trustedConf;
            for (String regex : trustedConf.split(",")) {
                String regexTrim = regex.trim();
                if (regexTrim.length() > 0) {
                    trustedDomainRegexes.add(regexTrim);
                }
            }
        }
    }
}
