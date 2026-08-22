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

public class CommandInjectionRule implements Rule {
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
                if (!taintedVars.isEmpty()) {
                    method.findAll(MethodCallExpr.class).forEach(call -> {
                        if (call.getNameAsString().equals("exec")) {
                            findings.add(new Finding("SEC-INJ-001",
                                    "Inyección de comandos detectada: una entrada de usuario llega a la ejecución del sistema.",
                                    sourceFile.getFileName().toString(), call.getBegin().map(p -> p.line).orElse(-1),
                                    CommandInjectionRule.this.settings.severity,
                                    "Usa ProcessBuilder con argumentos separados:<br><pre>new ProcessBuilder(\"cmd\", var)</pre>"));
                        }
                    });
                }
            }
        }, null);
        return findings;
    }
}
