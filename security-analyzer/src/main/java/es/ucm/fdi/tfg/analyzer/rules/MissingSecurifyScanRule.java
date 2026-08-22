package es.ucm.fdi.tfg.analyzer.rules;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import es.ucm.fdi.tfg.analyzer.core.Finding;
import es.ucm.fdi.tfg.analyzer.core.PolicyConfig;
import es.ucm.fdi.tfg.analyzer.core.Rule;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MissingSecurifyScanRule implements Rule {

    private PolicyConfig.RuleSettings settings;

    // El motor inyecta la configuración del XML mediante este método
    public void setSettings(PolicyConfig.RuleSettings settings) {
        this.settings = settings;
    }

    @Override
    public List<Finding> analyze(Path file) {
        List<Finding> findings = new ArrayList<>();

        try {
            // 1. Parseamos el archivo para generar el Árbol de Sintaxis Abstracta (AST)
            CompilationUnit cu = StaticJavaParser.parse(file);

            // 2. Buscamos todas las declaraciones de clases en el archivo
            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {

                // Comprobamos si la clase es un controlador de Spring
                boolean isRestController = clazz.getAnnotations().stream()
                        .anyMatch(a -> a.getNameAsString().equals("RestController") ||
                                a.getNameAsString().equals("Controller"));

                if (isRestController) {
                    // Comprobamos si tiene nuestras anotaciones de seguridad
                    boolean isSecured = clazz.getAnnotations().stream()
                            .anyMatch(a -> a.getNameAsString().equals("SecurifyScan") ||
                                    a.getNameAsString().equals("AutoSecureEndpoint"));

                    if (!isSecured) {
                        // Extraemos la línea exacta donde ocurre el problema
                        int line = clazz.getBegin().isPresent() ? clazz.getBegin().get().line : 0;

                        // 3. Creamos el hallazgo usando el constructor exacto de la clase Finding
                        // Constructor esperado: Finding(String id, String file, String description, int line, Severity severity, String remediation)
                        findings.add(new Finding(
                                "SEC-CI-001",
                                file.toString(),
                                "El controlador " + clazz.getNameAsString() + " carece de protección programática.",
                                line,
                                Finding.Severity.CRITICAL, // Uso del Enum interno para la severidad
                                "Añade @SecurifyScan(policy = \"...\") para habilitar la securización automática."
                        ));
                    }
                }
            });

        } catch (Exception e) {
            // Si el archivo no es código Java válido o no se puede leer, lo ignoramos de forma segura
        }

        return findings;
    }
}