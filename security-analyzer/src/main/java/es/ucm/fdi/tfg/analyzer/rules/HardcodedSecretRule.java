package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class HardcodedSecretRule implements Rule {
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
            public void visit(VariableDeclarator n, Void arg) {
                super.visit(n, arg);
                String name = n.getNameAsString().toLowerCase();
                if ((name.contains("password") || name.contains("secret") || name.contains("apikey")) && n.getInitializer().isPresent()) {
                    findings.add(new Finding("SEC-SECRET-001",
                            "Se ha detectado un posible secreto (contraseña/token) escrito en el código.",
                            sourceFile.getFileName().toString(), n.getBegin().map(p -> p.line).orElse(-1),
                            HardcodedSecretRule.this.settings.severity,
                            "Extrae el secreto a una variable de entorno:<br><pre>System.getenv(\"DB_PASSWORD\")</pre>"));
                }
            }
        }, null);
        return findings;
    }
}
