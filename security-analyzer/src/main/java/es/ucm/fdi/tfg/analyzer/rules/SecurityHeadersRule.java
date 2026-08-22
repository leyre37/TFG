package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SecurityHeadersRule implements Rule {
    private PolicyConfig.RuleSettings settings;

    @Override
    public void setSettings(PolicyConfig.RuleSettings settings) { this.settings = settings; }

    @Override
    public List<Finding> analyze(Path sourceFile) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String code = new String(Files.readAllBytes(sourceFile));

        // Solo analizamos archivos de configuración de seguridad
        if (!code.contains("HttpSecurity") && !code.contains("SecurityFilterChain")) return findings;

        CompilationUnit cu = StaticJavaParser.parse(code);

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr n, Void arg) {
                super.visit(n, arg);

                // Detectar si se configura el bloque de headers
                if (n.getNameAsString().equals("headers")) {
                    String fullChain = n.toString();

                    // 1. Verificar FrameOptions (Clickjacking)
                    if (!fullChain.contains("frameOptions")) {
                        addHeaderFinding(findings, sourceFile, n, "Falta configuración de X-Frame-Options (protección contra Clickjacking).",
                                "Añade: <br><pre>.headers(h -> h.frameOptions(f -> f.deny()))</pre>");
                    }

                    // 2. Verificar Content Security Policy (CSP)
                    if (!fullChain.contains("contentSecurityPolicy")) {
                        addHeaderFinding(findings, sourceFile, n, "Falta Content-Security-Policy (CSP) para mitigar ataques XSS.",
                                "Añade una política estricta:<br><pre>.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(\"default-src 'self'\")))</pre>");
                    }
                }
            }
        }, null);

        return findings;
    }

    private void addHeaderFinding(List<Finding> findings, Path file, MethodCallExpr n, String desc, String remed) {
        findings.add(new Finding("SEC-HEAD-001", desc, file.getFileName().toString(),
                n.getBegin().map(p -> p.line).orElse(-1), this.settings.severity, remed));
    }
}
