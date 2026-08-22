package es.ucm.fdi.tfg.analyzer.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PolicyConfig {
    public static class RuleSettings {
        public String ruleName;
        public boolean active;
        public Finding.Severity severity;

        public RuleSettings(String ruleName, boolean active, Finding.Severity severity) {
            this.ruleName = ruleName;
            this.active = active;
            this.severity = severity;
        }
    }
    public Map<String, RuleSettings> ruleMap = new HashMap<>();

    public static class VulnerableComponent {
        public String artifact, version, cve, severity, recommendation;
        public VulnerableComponent(String a, String v, String c, String s, String r) {
            this.artifact = a; this.version = v; this.cve = c; this.severity = s; this.recommendation = r;
        }
    }
    public List<VulnerableComponent> vulnerableComponents = new ArrayList<>();
    public List<String> allowedRoles = new ArrayList<>();
    public Finding.Severity failOnSeverity = Finding.Severity.CRITICAL;
}
