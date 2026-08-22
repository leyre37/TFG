package es.ucm.fdi.tfg.analyzer.core;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.google.auto.service.AutoService;
import es.ucm.fdi.tfg.analyzer.annotations.*;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.ElementKind;
import javax.tools.Diagnostic;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

@AutoService(Processor.class)
@SupportedAnnotationTypes({
        "es.ucm.fdi.tfg.analyzer.annotations.SecurifyScan",
        "es.ucm.fdi.tfg.analyzer.annotations.SensitiveParam",
        "es.ucm.fdi.tfg.analyzer.annotations.AutoSecureEndpoint",
        "es.ucm.fdi.tfg.analyzer.annotations.AutoCorsConfig",
        "es.ucm.fdi.tfg.analyzer.annotations.EnforceCsrf",
        "es.ucm.fdi.tfg.analyzer.annotations.AclScan",
        "es.ucm.fdi.tfg.analyzer.annotations.ValidateInput",
        "es.ucm.fdi.tfg.analyzer.annotations.AuditConfig",
        "es.ucm.fdi.tfg.analyzer.annotations.GeneratePreAuthorize",
        "es.ucm.fdi.tfg.analyzer.annotations.InjectSecurityPolicy",
        "es.ucm.fdi.tfg.analyzer.annotations.AutoDataMasking",
        "es.ucm.fdi.tfg.analyzer.annotations.EnforceInputValidation"
})
@SupportedSourceVersion(SourceVersion.RELEASE_17)
public class SecurityProcessor extends AbstractProcessor {

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        if (annotations.isEmpty()) {
            return false;
        }

        Messager messager = processingEnv.getMessager();
        messager.printMessage(Diagnostic.Kind.NOTE, "====== Iniciando TFG Security Framework - Compilación ======");

        // Cargar la política de seguridad global al inicio
        PolicyConfig policy = new PolicyConfig();
        try {
            Path policyPath = Paths.get("policy.xml").toAbsolutePath().normalize();
            if (Files.exists(policyPath)) {
                policy = PolicyLoader.load(policyPath.toString());
            }
        } catch (Exception e) {
            messager.printMessage(Diagnostic.Kind.WARNING, "No se pudo cargar policy.xml correctamente. Usando configuración por defecto.");
        }

        // -----------------------------------------------------------------------------
        // Fase 3 - Bloqueo CI/CD (Gatekeeper) para endpoints no protegidos
        // -----------------------------------------------------------------------------
        for (Element element : roundEnv.getRootElements()) {
            if (element.getKind() == ElementKind.CLASS) {
                TypeElement typeElement = (TypeElement) element;

                // Comprobar si tiene @RestController o @Controller de Spring
                boolean isController = typeElement.getAnnotationMirrors().stream()
                        .anyMatch(am -> am.getAnnotationType().toString().contains("RestController") ||
                                am.getAnnotationType().toString().contains("Controller"));

                if (isController) {
                    // Comprobar si tiene las anotaciones de seguridad
                    boolean hasSecurifyScan = typeElement.getAnnotationMirrors().stream()
                            .anyMatch(am -> am.getAnnotationType().toString().contains("SecurifyScan"));
                    boolean hasAutoSecure = typeElement.getAnnotationMirrors().stream()
                            .anyMatch(am -> am.getAnnotationType().toString().contains("AutoSecureEndpoint"));

                    // Si es un controlador sin protección, bloqueamos la compilación
                    if (!hasSecurifyScan && !hasAutoSecure) {
                        messager.printMessage(
                                Diagnostic.Kind.ERROR,
                                "BLOQUEO CI/CD: Vulnerabilidad Crítica detectada. " +
                                        "El controlador '" + typeElement.getSimpleName() +
                                        "' expone endpoints sin protección programática. " +
                                        "Debe incluir @SecurifyScan o @AutoSecureEndpoint.",
                                element
                        );
                    }
                }
            }
        }

        boolean generateMasking = false;
        boolean generateAutoDataMasking = false;
        boolean generateAdvanced = false;

        String[] corsOrigins = null;
        String[] csrfMethods = null;

        for (Element element : roundEnv.getElementsAnnotatedWith(SecurifyScan.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> Analizando controlador: " + element.getSimpleName());
        }
        for (Element element : roundEnv.getElementsAnnotatedWith(SensitiveParam.class)) {
            generateMasking = true;
        }
        for (Element element : roundEnv.getElementsAnnotatedWith(AutoSecureEndpoint.class)) {}
        for (Element element : roundEnv.getElementsAnnotatedWith(AutoCorsConfig.class)) {
            corsOrigins = element.getAnnotation(AutoCorsConfig.class).origins();
        }
        for (Element element : roundEnv.getElementsAnnotatedWith(EnforceCsrf.class)) {
            csrfMethods = element.getAnnotation(EnforceCsrf.class).methods();
        }

        for (Element element : roundEnv.getElementsAnnotatedWith(AclScan.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [ACL] Control de acceso programado para el método: " + element.getSimpleName());
            generateAdvanced = true;
        }
        for (Element element : roundEnv.getElementsAnnotatedWith(ValidateInput.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [VALIDACIÓN] Validación de entrada forzada en método: " + element.getSimpleName());
            generateAdvanced = true;
        }
        for (Element element : roundEnv.getElementsAnnotatedWith(AuditConfig.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [AUDITORÍA] Registro GDPR configurado para método: " + element.getSimpleName());
            generateAdvanced = true;
        }

        // -----------------------------------------------------------------------------
        // Fase 4 - Intercepción de @GeneratePreAuthorize para control de acceso
        // -----------------------------------------------------------------------------
        for (Element element : roundEnv.getElementsAnnotatedWith(GeneratePreAuthorize.class)) {
            GeneratePreAuthorize annotation = element.getAnnotation(GeneratePreAuthorize.class);
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [PRE-AUTHORIZE] Generando ACL dinámico para: " + annotation.roleSource());
            generateAdvanced = true;
        }

        for (Element element : roundEnv.getElementsAnnotatedWith(InjectSecurityPolicy.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [POLICY] Generando política global inyectada para: " + element.getSimpleName());
            try {
                // Genera la política de red leyendo el YAML
                SecurityCodeGenerator.generateSecurityPolicyConfig(processingEnv.getFiler(), element.getSimpleName().toString(), "es.ucm.fdi.tfg.demo");
            } catch (Exception e) {
                messager.printMessage(Diagnostic.Kind.ERROR, "Error al generar política inyectada: " + e.getMessage());
            }
        }

        for (Element element : roundEnv.getElementsAnnotatedWith(AutoDataMasking.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [AUTO-MASKING] Aspecto de ofuscación programado para método: " + element.getSimpleName());
            generateAutoDataMasking = true;
        }

        for (Element element : roundEnv.getElementsAnnotatedWith(EnforceInputValidation.class)) {
            messager.printMessage(Diagnostic.Kind.NOTE, "-> [ENFORCE-VALIDATION] Detectada necesidad de reescribir AST para inyectar @Valid en: " + element.getSimpleName());
            // La reescritura física del AST la delegaríamos en el motor de JavaParser
        }

        // Ejecutar Análisis de AST pasándole la política ya cargada
        List<Finding> allFindings = lanzarMotorAST(messager, policy);

        // --- NUEVO: Fase 5 - Interrupción por umbral de severidad (Gatekeeper global) ---
        boolean buildFailed = false;
        if (policy.failOnSeverity != null) {
            for (Finding finding : allFindings) {
                // Si la vulnerabilidad encontrada iguala o supera el umbral configurado
                if (finding.getSeverity().ordinal() >= policy.failOnSeverity.ordinal()) {
                    messager.printMessage(
                            Diagnostic.Kind.ERROR,
                            "BLOQUEO CI/CD: Vulnerabilidad de nivel " + finding.getSeverity() + " detectada. " +
                                    "El umbral de fallo del proyecto está configurado en " + policy.failOnSeverity + ".\n" +
                                    "-> Archivo: " + finding.getFilePath() + " (Línea " + finding.getLineNumber() + ")\n" +
                                    "-> Detalle: " + finding.getDescription()
                    );
                    buildFailed = true;
                }
            }
        }

        // Si se encontraron errores graves, detenemos el procesador y con ello la compilación
        if (buildFailed) {
            messager.printMessage(Diagnostic.Kind.ERROR, "La compilación se ha detenido por fallos de seguridad (Shift-Left Security).");
            return false;
        }
        // ---------------------------------------------------------------------------------

        // Generación de Red
        if (!allFindings.isEmpty() || corsOrigins != null || csrfMethods != null) {
            try {
                Path yamlPath = Paths.get("security-policies.yml").toAbsolutePath().normalize();
                YamlSecurityConfig yamlConfig = null;
                if (Files.exists(yamlPath)) { yamlConfig = YamlPolicyLoader.load(yamlPath); }
                SecurityCodeGenerator.generateSecurityConfig(processingEnv.getFiler(), yamlConfig, "REST_STRICT", corsOrigins, csrfMethods);
            } catch (Exception e) {}
        }

        // Generación de Privacidad de logs (Antiguo @SensitiveParam)
        if (generateMasking) {
            try { MaskingCodeGenerator.generateMaskingAspect(processingEnv.getFiler()); } catch (Exception e) {}
        }

        // Generación de Privacidad Activa (Nuevo @AutoDataMasking)
        if (generateAutoDataMasking) {
            try {
                messager.printMessage(Diagnostic.Kind.NOTE, "-> Generando AutoMaskingAspect.java...");
                MaskingCodeGenerator.generateAutoDataMaskingAspect(processingEnv.getFiler(), "es.ucm.fdi.tfg.demo");
            } catch (Exception e) {}
        }

        // Generación de Lógica Avanzada
        if (generateAdvanced) {
            try {
                messager.printMessage(Diagnostic.Kind.NOTE, "-> Generando políticas avanzadas de Negocio (ACL, Validación, Auditoría)...");
                AdvancedSecurityCodeGenerator.generateAdvancedAspect(processingEnv.getFiler());
                messager.printMessage(Diagnostic.Kind.NOTE, "-> ¡AutoAdvancedSecurityAspect.java generada con éxito!");
            } catch (Exception e) {
                messager.printMessage(Diagnostic.Kind.ERROR, "Error al generar Aspecto Avanzado: " + e.getMessage());
            }
        }

        return true;
    }

    // -----------------------------------------------------------------------------
    // Modificación de Árbol de Sintaxis para @EnforceInputValidation
    // -----------------------------------------------------------------------------
    private void enforceValidationOnMethod(MethodDeclaration method, CompilationUnit cu) {
        cu.addImport("jakarta.validation.constraints.Email");
        cu.addImport("jakarta.validation.Valid");

        for (com.github.javaparser.ast.body.Parameter param : method.getParameters()) {
            String paramName = param.getNameAsString().toLowerCase();
            if (paramName.contains("email") && !param.isAnnotationPresent("Email")) {
                param.addAnnotation("Email");
                System.out.println("[SEC-VALIDATION] Anotación @Email inyectada dinámicamente en el parámetro: " + param.getName());
            }
        }

        method.findAncestor(ClassOrInterfaceDeclaration.class).ifPresent(c -> {
            if (!c.isAnnotationPresent("Validated")) {
                cu.addImport("org.springframework.validation.annotation.Validated");
                c.addAnnotation("Validated");
            }
        });
    }

    private List<Finding> lanzarMotorAST(Messager messager, PolicyConfig policy) {
        List<Finding> allFindings = new ArrayList<>();
        try {
            Path demoAppRoot = Paths.get("demo-app").toAbsolutePath().normalize();
            Path demoAppSrc = demoAppRoot.resolve("src/main/java");
            CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
            combinedTypeSolver.add(new ReflectionTypeSolver());
            if (Files.exists(demoAppSrc)) { combinedTypeSolver.add(new JavaParserTypeSolver(demoAppSrc)); }
            JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
            StaticJavaParser.getConfiguration().setSymbolResolver(symbolSolver);


            List<Rule> activeRules = new ArrayList<>();
            for (Map.Entry<String, PolicyConfig.RuleSettings> entry : policy.ruleMap.entrySet()) {
                PolicyConfig.RuleSettings settings = entry.getValue();
                if (settings.active) {
                    try {
                        String className = "es.ucm.fdi.tfg.analyzer.rules." + settings.ruleName;
                        Rule rule = (Rule) Class.forName(className).getDeclaredConstructor().newInstance();
                        rule.setSettings(settings);
                        if (rule.getClass().getSimpleName().equals("SpELSecurityRule")) {
                            rule.getClass().getMethod("setFullPolicy", PolicyConfig.class).invoke(rule, policy);
                        }
                        activeRules.add(rule);
                    } catch (Exception e) {}
                }
            }
            if (!Files.exists(demoAppRoot)) return allFindings;
            try (Stream<Path> paths = Files.walk(demoAppRoot)) {
                paths.forEach(file -> {
                    String fileName = file.getFileName().toString();
                    if (fileName.equals("pom.xml")) {
                        try {
                            Class<?> depRuleClass = Class.forName("es.ucm.fdi.tfg.analyzer.rules.DependencyRule");
                            Rule depRule = (Rule) depRuleClass.getDeclaredConstructor().newInstance();
                            depRuleClass.getMethod("setPolicy", PolicyConfig.class).invoke(depRule, policy);
                            allFindings.addAll(depRule.analyze(file));
                        } catch (Exception e) {}
                    }
                    if (fileName.endsWith(".java")) {
                        for (Rule rule : activeRules) { try { allFindings.addAll(rule.analyze(file)); } catch (Exception e) {} }
                    }
                });
            }
        } catch (Exception e) {}
        return allFindings;
    }
}