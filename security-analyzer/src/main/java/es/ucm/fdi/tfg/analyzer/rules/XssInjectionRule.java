package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class XssInjectionRule implements Rule {
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
                method.findAll(ReturnStmt.class).forEach(ret -> {
                    if (taintedVars.stream().anyMatch(v -> ret.toString().contains(v))) {
                        findings.add(new Finding("SEC-INJ-003",
                                "Posible XSS reflejado: la entrada del usuario se devuelve al navegador sin ser saneada.",
                                sourceFile.getFileName().toString(), ret.getBegin().map(p -> p.line).orElse(-1),
                                XssInjectionRule.this.settings.severity,
                                "Escapa la salida HTML:<br><pre>HtmlUtils.htmlEscape(userInput)</pre>"));
                    }
                });
            }
        }, null);
        return findings;
    }
}
