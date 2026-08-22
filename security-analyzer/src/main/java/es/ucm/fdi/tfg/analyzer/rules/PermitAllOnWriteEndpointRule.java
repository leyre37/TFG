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

public class PermitAllOnWriteEndpointRule implements Rule {
    private PolicyConfig.RuleSettings settings;

    @Override
    public void setSettings(PolicyConfig.RuleSettings settings) { this.settings = settings; }

    @Override
    public List<Finding> analyze(Path sourceFile) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String code = new String(Files.readAllBytes(sourceFile));
        CompilationUnit cu = StaticJavaParser.parse(code);

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr n, Void arg) {
                super.visit(n, arg);
                if (n.getNameAsString().equals("permitAll") && (n.toString().contains("POST") || n.toString().contains("DELETE"))) {
                    findings.add(new Finding("SEC-AUTH-001",
                            "Uso peligroso de 'permitAll()' en una operación de escritura.",
                            sourceFile.getFileName().toString(), n.getBegin().map(p -> p.line).orElse(-1),
                            PermitAllOnWriteEndpointRule.this.settings.severity,
                            "Protege los métodos de escritura:<br><pre>.requestMatchers(HttpMethod.POST, \"/**\").authenticated()</pre>"));
                }
            }
        }, null);
        return findings;
    }
}
