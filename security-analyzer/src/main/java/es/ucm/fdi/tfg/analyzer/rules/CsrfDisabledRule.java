package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
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

public class CsrfDisabledRule implements Rule {
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
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                if (call.getNameAsString().equals("disable")) {
                    boolean isCsrf = call.getScope().map(s -> s.toString().contains("csrf")).orElse(false);
                    if (isCsrf) {
                        int line = call.getBegin().map(p -> p.line).orElse(-1);
                        findings.add(new Finding("SPRING-SEC-001",
                                "La protección CSRF está desactivada. Esto expone la aplicación a ataques de falsificación de petición.",
                                sourceFile.getFileName().toString(), line, CsrfDisabledRule.this.settings.severity,
                                "Habilita la protección por defecto:<br><pre>.csrf(Customizer.withDefaults())</pre>"));
                    }
                }
            }
        }, null);
        return findings;
    }
}
