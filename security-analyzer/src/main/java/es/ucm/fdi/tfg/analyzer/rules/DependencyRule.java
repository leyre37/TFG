package es.ucm.fdi.tfg.analyzer.rules;

import es.ucm.fdi.tfg.analyzer.core.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class DependencyRule implements Rule {
    private PolicyConfig policy; // Necesitamos toda la política para ver los componentes

    @Override
    public void setSettings(PolicyConfig.RuleSettings settings) { /* No se usa aquí */ }

    // Nuevo método para pasarle los componentes vulnerables
    public void setPolicy(PolicyConfig policy) { this.policy = policy; }

    @Override
    public List<Finding> analyze(Path sourceFile) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String content = new String(Files.readAllBytes(sourceFile));

        for (PolicyConfig.VulnerableComponent v : policy.vulnerableComponents) {
            // Buscamos si el artefacto y la versión están en el pom.xml
            if (content.contains(v.artifact) && content.contains(v.version)) {
                findings.add(new Finding(
                        v.cve,
                        "Componente vulnerable detectado: " + v.artifact + " (Versión " + v.version + ")",
                        sourceFile.getFileName().toString(),
                        0, // En el pom.xml marcamos línea 0 por simplicidad
                        Finding.Severity.valueOf(v.severity),
                        "Riesgo de seguridad conocido. Solución: <br><pre>Actualizar " + v.artifact + " a una versión segura.</pre>"
                ));
            }
        }
        return findings;
    }
}
