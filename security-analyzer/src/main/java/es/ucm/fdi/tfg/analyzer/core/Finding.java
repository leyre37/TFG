package es.ucm.fdi.tfg.analyzer.core;


public class Finding {
    public enum Severity { INFO, WARNING, CRITICAL }

    private final String ruleId;
    private final String description;
    private final String filePath;
    private final int lineNumber;
    private final Severity severity;
    private final String remediation; // Para tratar bloques de código/parches

    public Finding(String ruleId, String desc, String file, int line, Severity sev, String remediation) {
        this.ruleId = ruleId;
        this.description = desc;
        this.filePath = file;
        this.lineNumber = line;
        this.severity = sev;
        this.remediation = remediation;
    }

    // Getters para el generador de informes
    public String getRuleId() { return ruleId; }
    public String getDescription() { return description; }
    public String getFilePath() { return filePath; }
    public int getLineNumber() { return lineNumber; }
    public Severity getSeverity() { return severity; }
    public String getRemediation() { return remediation; }

    @Override
    public String toString() {
        return String.format(
                "[%s] ID: %s en %s (Línea %d)%n" +
                        "    Detalle: %s%n" +
                        "    SOLUCIÓN SUGERIDA: %s",
                severity, ruleId, filePath, lineNumber, description, remediation
        );
    }
}
