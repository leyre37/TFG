package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
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

public class SqlInjectionRule implements Rule {
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
            public void visit(MethodDeclaration method, Void arg) {
                super.visit(method, arg);
                List<String> taintedVars = new ArrayList<>();
                for (Parameter p : method.getParameters()) if (p.isAnnotationPresent("RequestParam")) taintedVars.add(p.getNameAsString());
                method.findAll(MethodCallExpr.class).forEach(call -> {
                    if (call.getNameAsString().equals("executeQuery") && call.toString().contains("+")) {
                        findings.add(new Finding("SEC-INJ-002",
                                "Inyección SQL detectada: se concatenan parámetros directamente en la consulta.",
                                sourceFile.getFileName().toString(), call.getBegin().map(p -> p.line).orElse(-1),
                                SqlInjectionRule.this.settings.severity,
                                "Usa consultas parametrizadas:<br><pre>jdbcTemplate.query(\"SELECT... WHERE id = ?\", id)</pre>"));
                    }
                });
            }
        }, null);
        return findings;
    }
}
