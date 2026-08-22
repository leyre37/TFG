package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class InsecureRandomRule implements Rule {
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
            public void visit(ObjectCreationExpr n, Void arg) {
                super.visit(n, arg);
                if (n.getTypeAsString().equals("Random")) {
                    findings.add(new Finding("SEC-CRYPTO-002",
                            "Generador de números aleatorios inseguro detectado.",
                            sourceFile.getFileName().toString(), n.getBegin().map(p -> p.line).orElse(-1),
                            InsecureRandomRule.this.settings.severity,
                            "Usa un generador criptográficamente fuerte:<br><pre>new SecureRandom()</pre>"));
                }
            }
        }, null);
        return findings;
    }
}
