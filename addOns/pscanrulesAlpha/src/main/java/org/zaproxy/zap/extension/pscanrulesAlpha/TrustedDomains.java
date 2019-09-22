package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

// TODO Move it to an "util" (find a better name) package?
public class TrustedDomains {
    private static final Logger LOG = Logger.getLogger(TrustedDomains.class);

    // TODO Replace "rules.domains.trusted" with RuleConfigParam.RULE_DOMAINS_TRUSTED once
    // available.
    public static final String TRUSTED_DOMAINS_PROPERTY = "rules.domains.trusted";
    private String trustedConfig = "";
    private List<Pattern> trustedDomainRegexesPatterns = new ArrayList<>();

    boolean isIncluded(String link) {
        // check the trusted domains
        return trustedDomainRegexesPatterns.stream()
                .anyMatch(regex -> regex.matcher(link).matches());
    }

    void update(String trustedConf) {
        // TODO use hashCode?
        if (!trustedConf.equals(this.trustedConfig)) {
            // Its changed
            trustedDomainRegexesPatterns.clear();
            this.trustedConfig = trustedConf;
            for (String regex : trustedConf.split(",")) {
                String regexTrim = regex.trim();
                if (!regexTrim.isEmpty()) {
                    try{
                        trustedDomainRegexesPatterns.add(Pattern.compile(regexTrim));
                    } catch (Exception e) {
                        LOG.warn("Invalid regex in rule " + TRUSTED_DOMAINS_PROPERTY + ": " + regex, e);
                    }
                }
            }
        }
    }
}
