package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
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

public class PasswordEncoderInsecureRule implements Rule {
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
                if (n.getTypeAsString().equals("NoOpPasswordEncoder")) {
                    addFinding(findings, sourceFile, n.getBegin().map(p -> p.line).orElse(-1),
                            "Codificador NoOp detectado. Las contraseñas se almacenan en texto plano.",
                            "Usa un codificador seguro:<br><pre>new BCryptPasswordEncoder()</pre>");
                }
            }

            @Override
            public void visit(MethodCallExpr n, Void arg) {
                super.visit(n, arg);
                if (n.getNameAsString().equals("getInstance") && n.toString().contains("MD5")) {
                    addFinding(findings, sourceFile, n.getBegin().map(p -> p.line).orElse(-1),
                            "Algoritmo de hash MD5 inseguro detectado.",
                            "Usa un algoritmo moderno:<br><pre>new BCryptPasswordEncoder()</pre>");
                }
            }
        }, null);
        return findings;
    }

    private void addFinding(List<Finding> findings, Path file, int line, String desc, String remed) {
        findings.add(new Finding("SEC-PWD-001", desc, file.getFileName().toString(), line, this.settings.severity, remed));
    }
}
