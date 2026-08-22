package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CorsMisconfigurationRule implements Rule {
    private PolicyConfig.RuleSettings settings;

    @Override
    public void setSettings(PolicyConfig.RuleSettings settings) { this.settings = settings; }

    @Override
    public List<Finding> analyze(Path sourceFile) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String code = new String(Files.readAllBytes(sourceFile));
        if (!code.contains("allowedOrigins")) return findings;
        CompilationUnit cu = StaticJavaParser.parse(code);

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr n, Void arg) {
                super.visit(n, arg);
                if (n.toString().contains("allowCredentials(true)") && code.contains("\"*\"")) {
                    findings.add(new Finding("SEC-CORS-001",
                            "Configuración de CORS insegura: se permite el origen comodín '*' con credenciales.",
                            sourceFile.getFileName().toString(), n.getBegin().map(p -> p.line).orElse(-1),
                            CorsMisconfigurationRule.this.settings.severity,
                            "Define dominios específicos en lugar de '*':<br><pre>config.setAllowedOrigins(List.of(\"https://app.com\"))</pre>"));
                }
            }
        }, null);
        return findings;
    }
}
