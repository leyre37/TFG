package es.ucm.fdi.tfg.analyzer.core;

import com.squareup.javapoet.*;

import javax.annotation.processing.Filer;
import javax.lang.model.element.Modifier;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AdvancedSecurityCodeGenerator {

    public static void generateAdvancedAspect(Filer filer) throws IOException {
        ClassName aspectClass = ClassName.get("org.aspectj.lang.annotation", "Aspect");
        ClassName configurationClass = ClassName.get("org.springframework.context.annotation", "Configuration");
        ClassName beforeClass = ClassName.get("org.aspectj.lang.annotation", "Before");
        ClassName joinPointClass = ClassName.get("org.aspectj.lang", "JoinPoint");
        ClassName methodSignatureClass = ClassName.get("org.aspectj.lang.reflect", "MethodSignature");

        ClassName securityContextHolderClass = ClassName.get("org.springframework.security.core.context", "SecurityContextHolder");
        ClassName authenticationClass = ClassName.get("org.springframework.security.core", "Authentication");
        ClassName accessDeniedExceptionClass = ClassName.get("org.springframework.security.access", "AccessDeniedException");
        ClassName illegalArgumentExceptionClass = ClassName.get("java.lang", "IllegalArgumentException");

        ClassName loggerClass = ClassName.get("org.slf4j", "Logger");
        ClassName loggerFactoryClass = ClassName.get("org.slf4j", "LoggerFactory");

        ClassName aclScanClass = ClassName.get("es.ucm.fdi.tfg.analyzer.annotations", "AclScan");
        ClassName validateInputClass = ClassName.get("es.ucm.fdi.tfg.analyzer.annotations", "ValidateInput");
        ClassName auditConfigClass = ClassName.get("es.ucm.fdi.tfg.analyzer.annotations", "AuditConfig");

        // Clase de la nueva anotación de la Fase 4
        ClassName generatePreAuthClass = ClassName.get("es.ucm.fdi.tfg.analyzer.annotations", "GeneratePreAuthorize");

        FieldSpec loggerField = FieldSpec.builder(loggerClass, "logger")
                .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
                .initializer("$T.getLogger(AutoAdvancedSecurityAspect.class)", loggerFactoryClass)
                .build();

        // Ampliamos el pointcut para que también intercepte @GeneratePreAuthorize
        MethodSpec.Builder interceptMethod = MethodSpec.methodBuilder("enforceAdvancedSecurity")
                .addModifiers(Modifier.PUBLIC)
                .addParameter(joinPointClass, "joinPoint")
                .addAnnotation(AnnotationSpec.builder(beforeClass)
                        .addMember("value", "\"@annotation(es.ucm.fdi.tfg.analyzer.annotations.AclScan) || " +
                                "@annotation(es.ucm.fdi.tfg.analyzer.annotations.ValidateInput) || " +
                                "@annotation(es.ucm.fdi.tfg.analyzer.annotations.AuditConfig) || " +
                                "@annotation(es.ucm.fdi.tfg.analyzer.annotations.GeneratePreAuthorize)\"")
                        .build());

        Map<String, Object> vars = new HashMap<>();
        vars.put("methodSig", methodSignatureClass);
        vars.put("auditCls", auditConfigClass);
        vars.put("authCls", authenticationClass);
        vars.put("secCtxHolder", securityContextHolderClass);
        vars.put("aclCls", aclScanClass);
        vars.put("accessDeniedEx", accessDeniedExceptionClass);
        vars.put("validateCls", validateInputClass);
        vars.put("illegalArgEx", illegalArgumentExceptionClass);
        vars.put("genAuthCls", generatePreAuthClass); // Inyectamos la nueva clase
        vars.put("regexEmail", "^[A-Za-z0-9+_.-]+@(.+)$");

        interceptMethod.addNamedCode(
                "$methodSig:T signature = ($methodSig:T) joinPoint.getSignature();\n" +
                        "java.lang.reflect.Method method = signature.getMethod();\n" +
                        "Object[] args = joinPoint.getArgs();\n\n" +

                        "// --- LÓGICA DE AUDITORÍA (@AuditConfig) ---\n" +
                        "if (method.isAnnotationPresent($auditCls:T.class)) {\n" +
                        "    $auditCls:T audit = method.getAnnotation($auditCls:T.class);\n" +
                        "    $authCls:T auth = $secCtxHolder:T.getContext().getAuthentication();\n" +
                        "    String username = (auth != null) ? auth.getName() : \"ANONYMOUS\";\n" +
                        "    logger.info(\"[AUDITORÍA TFG] Usuario: '{}' ejecutó Acción: '{}' en método: '{}'\", username, audit.action(), signature.getName());\n" +
                        "}\n\n" +

                        "// --- LÓGICA DE CONTROL DE ACCESO (ACL - @AclScan) ---\n" +
                        "if (method.isAnnotationPresent($aclCls:T.class)) {\n" +
                        "    $aclCls:T acl = method.getAnnotation($aclCls:T.class);\n" +
                        "    $authCls:T auth = $secCtxHolder:T.getContext().getAuthentication();\n" +
                        "    boolean hasRole = false;\n" +
                        "    if (auth != null) {\n" +
                        "        hasRole = auth.getAuthorities().stream()\n" +
                        "            .anyMatch(a -> a.getAuthority().equals(acl.role()));\n" +
                        "    }\n" +
                        "    if (!hasRole) {\n" +
                        "        logger.warn(\"[ACL BLOQUEADO] Acceso denegado al método '{}'. Se requería el rol: {}\", signature.getName(), acl.role());\n" +
                        "        throw new $accessDeniedEx:T(\"Acceso denegado: No tienes el rol \" + acl.role());\n" +
                        "    }\n" +
                        "}\n\n" +

                        "// --- LÓGICA DE PRE-AUTHORIZE DINÁMICA (@GeneratePreAuthorize) ---\n" +
                        "if (method.isAnnotationPresent($genAuthCls:T.class)) {\n" +
                        "    $genAuthCls:T genAuth = method.getAnnotation($genAuthCls:T.class);\n" +
                        "    String roleSource = genAuth.roleSource();\n" +
                        "    String[] parts = roleSource.split(\"::\");\n" +
                        "    if (parts.length == 2) {\n" +
                        "        String entity = parts[0];\n" +
                        "        String permission = parts[1];\n" +
                        "        logger.info(\"[SECURITY] Verificando permisos dinámicos ACL: hasPermission(id, '{}', '{}') en método '{}'\", entity, permission, signature.getName());\n" +
                        "        // Aquí se enlaza con el AclService de Spring Security\n" +
                        "    }\n" +
                        "}\n\n" +

                        "// --- LÓGICA DE VALIDACIÓN DE ENTRADAS (@ValidateInput) ---\n" +
                        "if (method.isAnnotationPresent($validateCls:T.class)) {\n" +
                        "    $validateCls:T val = method.getAnnotation($validateCls:T.class);\n" +
                        "    if (\"EMAIL\".equalsIgnoreCase(val.type())) {\n" +
                        "        for (Object arg : args) {\n" +
                        "            if (arg instanceof String) {\n" +
                        "                String email = (String) arg;\n" +
                        "                if (!email.matches($regexEmail:S)) {\n" +
                        "                    logger.error(\"[VALIDACIÓN FALLIDA] Formato de Email inválido detectado: {}\", email);\n" +
                        "                    throw new $illegalArgEx:T(\"Formato de entrada inválido: Se esperaba un Email\");\n" +
                        "                }\n" +
                        "            }\n" +
                        "        }\n" +
                        "    }\n" +
                        "}\n",
                vars
        );

        TypeSpec aspectConfigClass = TypeSpec.classBuilder("AutoAdvancedSecurityAspect")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(aspectClass)
                .addAnnotation(configurationClass)
                .addField(loggerField)
                .addMethod(interceptMethod.build())
                .build();

        JavaFile javaFile = JavaFile.builder("es.ucm.fdi.tfg.demo.security", aspectConfigClass)
                .indent("    ")
                .build();

        javaFile.writeTo(filer);
    }
}