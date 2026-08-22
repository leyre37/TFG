package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MissingPreAuthorizeRule implements Rule {
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
            public void visit(ClassOrInterfaceDeclaration n, Void arg) {
                super.visit(n, arg);
                if (n.getNameAsString().endsWith("Service")) {
                    for (MethodDeclaration method : n.getMethods()) {
                        if (method.isPublic() && !method.isAnnotationPresent("PreAuthorize") && !method.isAnnotationPresent("Secured")) {
                            findings.add(new Finding("SEC-AUTH-002",
                                    "Método de servicio público sin anotación de seguridad.",
                                    sourceFile.getFileName().toString(), method.getBegin().map(p -> p.line).orElse(-1),
                                    MissingPreAuthorizeRule.this.settings.severity,
                                    "Añade control de acceso al método:<br><pre>@PreAuthorize(\"hasRole('ADMIN')\")</pre>"));
                        }
                    }
                }
            }
        }, null);
        return findings;
    }
}
