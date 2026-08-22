package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import es.ucm.fdi.tfg.analyzer.core.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class SpELSecurityRule implements Rule {
    private PolicyConfig.RuleSettings settings;
    private PolicyConfig fullPolicy; // Para acceder a los roles del XML

    @Override
    public void setSettings(PolicyConfig.RuleSettings settings) { this.settings = settings; }

    // Método para inyectar la configuración global
    public void setFullPolicy(PolicyConfig policy) { this.fullPolicy = policy; }

    @Override
    public List<Finding> analyze(Path sourceFile) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String code = new String(Files.readAllBytes(sourceFile));
        CompilationUnit cu = StaticJavaParser.parse(code);

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            method.getAnnotations().forEach(anno -> {
                String name = anno.getNameAsString();
                if (name.equals("PreAuthorize") || name.equals("PostAuthorize")) {
                    String expr = anno.toString().toLowerCase();
                    int line = anno.getBegin().map(p -> p.line).orElse(-1);

                    // 1. Lógica Trivial
                    if (expr.contains("permitall") || expr.contains("true")) {
                        findings.add(new Finding("SEC-SPEL-001", "Expresión SpEL trivial (acceso total).",
                                sourceFile.getFileName().toString(), line, this.settings.severity,
                                "Define reglas de acceso específicas: <br><pre>@PreAuthorize(\"hasRole('USER')\")</pre>"));
                    }

                    // 2. Invocación de métodos (Peligroso si no está controlado)
                    if (expr.contains("@") || (expr.contains("(") && !expr.contains("hasrole") && !expr.contains("hasanyrole"))) {
                        findings.add(new Finding("SEC-SPEL-002", "Invocación de métodos externos en SpEL.",
                                sourceFile.getFileName().toString(), line, Finding.Severity.WARNING,
                                "Evita llamar a beans externos en SpEL si no es estrictamente necesario."));
                    }

                    // 3. Validación de Roles contra el XML (RBAC Dinámico)
                    if (expr.contains("hasrole")) {
                        boolean roleFound = false;
                        // Comprobamos si el rol escrito aparece en nuestra lista del policy.xml
                        for (String allowedRole : fullPolicy.allowedRoles) {
                            if (expr.contains(allowedRole.toLowerCase().replace("role_", ""))) {
                                roleFound = true;
                                break;
                            }
                        }
                        if (!roleFound) {
                            findings.add(new Finding("SEC-SPEL-003", "Rol no reconocido en el catálogo oficial.",
                                    sourceFile.getFileName().toString(), line, Finding.Severity.WARNING,
                                    "El rol no figura en policy.xml. Roles permitidos: <br><pre>" + fullPolicy.allowedRoles + "</pre>"));
                        }
                    }
                }
            });
        });
        return findings;
    }
}
