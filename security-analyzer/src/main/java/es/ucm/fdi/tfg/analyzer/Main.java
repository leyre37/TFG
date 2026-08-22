package es.ucm.fdi.tfg.analyzer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import es.ucm.fdi.tfg.analyzer.core.*;
import es.ucm.fdi.tfg.analyzer.rules.*;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) throws Exception {
        // 1. Configuración de rutas (Analizamos la raíz de demo-app)
        Path demoAppRoot = Paths.get("demo-app").toAbsolutePath().normalize();
        Path demoAppSrc = demoAppRoot.resolve("src/main/java");

        // 2. CONFIGURACIÓN DEL SYMBOL SOLVER (Taint Analysis)
        CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
        combinedTypeSolver.add(new ReflectionTypeSolver());
        if (Files.exists(demoAppSrc)) {
            combinedTypeSolver.add(new JavaParserTypeSolver(demoAppSrc));
        }
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
        StaticJavaParser.getConfiguration().setSymbolResolver(symbolSolver);

        // 3. CARGAR POLÍTICA DESDE XML
        System.out.println("Cargando política de seguridad desde policy.xml...");
        PolicyConfig policy = PolicyLoader.load("policy.xml");

        // 4. INSTANCIACIÓN DINÁMICA DE REGLAS (Reflection)
        List<Rule> activeRules = new ArrayList<>();
        for (Map.Entry<String, PolicyConfig.RuleSettings> entry : policy.ruleMap.entrySet()) {
            PolicyConfig.RuleSettings settings = entry.getValue();
            if (settings.active) {
                try {
                    String className = "es.ucm.fdi.tfg.analyzer.rules." + settings.ruleName;
                    Rule rule = (Rule) Class.forName(className).getDeclaredConstructor().newInstance();

                    // Inyección de configuración
                    rule.setSettings(settings);

                    // Caso especial: Regla SpEL necesita la política completa para los roles
                    if (rule instanceof SpELSecurityRule) {
                        ((SpELSecurityRule) rule).setFullPolicy(policy);
                    }

                    activeRules.add(rule);
                    System.out.println("Regla activada: " + entry.getKey() + " [" + settings.ruleName + "]");
                } catch (Exception e) {
                    System.err.println("No se pudo cargar la regla " + entry.getKey() + ": " + e.getMessage());
                }
            }
        }

        // 5. EJECUCIÓN DEL ANÁLISIS HÍBRIDO
        List<Finding> allFindings = new ArrayList<>();
        System.out.println("\nIniciando escaneo en: " + demoAppRoot);

        try (Stream<Path> paths = Files.walk(demoAppRoot)) {
            paths.forEach(file -> {
                String fileName = file.getFileName().toString();

                // --- Análisis SCA (pom.xml) ---
                if (fileName.equals("pom.xml")) {
                    DependencyRule depRule = new DependencyRule();
                    depRule.setPolicy(policy);
                    try {
                        allFindings.addAll(depRule.analyze(file));
                    } catch (Exception e) { /* ... */ }
                }

                // --- Análisis SAST (.java) ---
                if (fileName.endsWith(".java")) {
                    for (Rule rule : activeRules) {
                        try {
                            allFindings.addAll(rule.analyze(file));
                        } catch (Exception e) { /* ... */ }
                    }
                }
            });
        }

        // 6. GENERACIÓN DE REPORTES MULTI-FORMATO
        // A. Reporte TXT (Legacy)
        Path reportTxt = Paths.get("analisis-report.txt");
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(reportTxt))) {
            writer.println("REPORTE DE SEGURIDAD - " + new Date());
            allFindings.forEach(f -> writer.println(f.toString()));
        }

        // B. Reporte HTML (Visual e Interactivo)
        Path reportHtml = Paths.get("reporte-seguridad.html");
        HtmlReportGenerator.generate(reportHtml, allFindings);

        // C. Reporte JSON (Machine-Readable)
        Path reportJson = Paths.get("reporte-seguridad.json");
        JsonReportGenerator.generate(reportJson, allFindings);

        // 7. FINALIZACIÓN
        System.out.println("\n-------------------------------------------------------");
        System.out.println("ANÁLISIS COMPLETADO. Hallazgos totales: " + allFindings.size());
        System.out.println("Reporte Visual: " + reportHtml.toAbsolutePath());
        System.out.println("Reporte JSON:   " + reportJson.toAbsolutePath());
        System.out.println("-------------------------------------------------------");
    }
}
