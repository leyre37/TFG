package es.ucm.fdi.tfg.analyzer.core;

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.TypeSpec;

import javax.annotation.processing.Filer;
import javax.lang.model.element.Modifier;
import java.io.IOException;

public class SecurityCodeGenerator {

    public static void generateSecurityConfig(Filer filer, YamlSecurityConfig config, String activePolicyName, String[] corsOrigins, String[] csrfMethods) throws IOException {

        YamlSecurityConfig.PolicyDetail policy = null;
        if (config != null && config.policies != null) {
            policy = config.policies.get(activePolicyName);
        }

        ClassName configurationClass = ClassName.get("org.springframework.context.annotation", "Configuration");
        ClassName beanClass = ClassName.get("org.springframework.context.annotation", "Bean");
        ClassName securityFilterChainClass = ClassName.get("org.springframework.security.web", "SecurityFilterChain");
        ClassName httpSecurityClass = ClassName.get("org.springframework.security.config.annotation.web.builders", "HttpSecurity");

        MethodSpec.Builder filterChainMethod = MethodSpec.methodBuilder("securityFilterChain")
                .addAnnotation(beanClass)
                .addModifiers(Modifier.PUBLIC)
                .addException(Exception.class)
                .returns(securityFilterChainClass)
                .addParameter(httpSecurityClass, "http");

        filterChainMethod.addCode("http\n");

        // 1. Autorización Base
        if (policy != null && policy.access != null) {
            filterChainMethod.addCode("    .authorizeHttpRequests(auth -> auth\n");
            String accessCode = policy.access.replace("'", "\"");
            filterChainMethod.addCode("        .anyRequest().$L)\n", accessCode);
        }

        // 2. Inyección dinámica de CORS (@AutoCorsConfig)
        if (corsOrigins != null && corsOrigins.length > 0) {
            filterChainMethod.addCode("    .cors(cors -> cors.configurationSource(corsConfigurationSource()))\n");
        }

        // 3. Inyección dinámica de CSRF (@EnforceCsrf)
        if (csrfMethods != null && csrfMethods.length > 0) {
            StringBuilder methodsStr = new StringBuilder();
            for(int i = 0; i < csrfMethods.length; i++) {
                methodsStr.append("\"").append(csrfMethods[i]).append("\"");
                if(i < csrfMethods.length - 1) methodsStr.append(", ");
            }
            filterChainMethod.addCode("    .csrf(csrf -> csrf.requireCsrfProtectionMatcher(\n");
            filterChainMethod.addCode("        request -> java.util.Arrays.asList($L).contains(request.getMethod())))\n", methodsStr.toString());
        }
        else if (policy != null && "required".equalsIgnoreCase(policy.csrf)) {
            // Si no hay anotación pero el YAML dice 'required', bloqueamos lo básico
            filterChainMethod.addCode("    .csrf(csrf -> csrf.requireCsrfProtectionMatcher(request -> !request.getMethod().equals(\"GET\")))\n");
        }

        filterChainMethod.addCode("    ;\n");
        filterChainMethod.addStatement("return http.build()");

        // Empezamos a construir la clase principal
        TypeSpec.Builder securityConfigClassBuilder = TypeSpec.classBuilder("AutoSecurityConfig")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(configurationClass)
                .addMethod(filterChainMethod.build());

        // 4. Creación del bean de CORS
        if (corsOrigins != null && corsOrigins.length > 0) {
            ClassName corsConfigSourceClass = ClassName.get("org.springframework.web.cors", "CorsConfigurationSource");
            ClassName corsConfigClass = ClassName.get("org.springframework.web.cors", "CorsConfiguration");
            ClassName urlBasedCorsClass = ClassName.get("org.springframework.web.cors", "UrlBasedCorsConfigurationSource");
            ClassName listClass = ClassName.get("java.util", "List");

            StringBuilder originsStr = new StringBuilder();
            for(int i = 0; i < corsOrigins.length; i++) {
                originsStr.append("\"").append(corsOrigins[i]).append("\"");
                if(i < corsOrigins.length - 1) originsStr.append(", ");
            }

            MethodSpec corsBeanMethod = MethodSpec.methodBuilder("corsConfigurationSource")
                    .addModifiers(Modifier.PRIVATE)
                    .returns(corsConfigSourceClass)
                    .addStatement("$T config = new $T()", corsConfigClass, corsConfigClass)
                    .addStatement("config.setAllowedOrigins($T.of($L))", listClass, originsStr.toString())
                    .addStatement("config.setAllowedMethods($T.of(\"GET\", \"POST\", \"PUT\", \"DELETE\"))", listClass)
                    .addStatement("$T source = new $T()", urlBasedCorsClass, urlBasedCorsClass)
                    .addStatement("source.registerCorsConfiguration(\"/**\", config)")
                    .addStatement("return source")
                    .build();

            securityConfigClassBuilder.addMethod(corsBeanMethod);
        }

        // 5. Escribir el archivo
        JavaFile javaFile = JavaFile.builder("es.ucm.fdi.tfg.demo.security", securityConfigClassBuilder.build())
                .indent("    ")
                .build();

        javaFile.writeTo(filer);
    }

    // Lógica para @InjectSecurityPolicy
    public static void generateSecurityPolicyConfig(Filer filer, String className, String packageName) throws IOException {
        ClassName configurationClass = ClassName.get("org.springframework.context.annotation", "Configuration");
        ClassName beanClass = ClassName.get("org.springframework.context.annotation", "Bean");
        ClassName corsConfigSourceClass = ClassName.get("org.springframework.web.cors", "CorsConfigurationSource");
        ClassName corsConfigClass = ClassName.get("org.springframework.web.cors", "CorsConfiguration");
        ClassName urlBasedCorsClass = ClassName.get("org.springframework.web.cors", "UrlBasedCorsConfigurationSource");
        ClassName listClass = ClassName.get("java.util", "List");

        MethodSpec corsBeanMethod = MethodSpec.methodBuilder("corsConfigurationSource")
                .addAnnotation(beanClass)
                .addModifiers(Modifier.PUBLIC)
                .returns(corsConfigSourceClass)
                .addStatement("$T config = new $T()", corsConfigClass, corsConfigClass)
                .addStatement("config.setAllowedOrigins($T.of($S))", listClass, "https://trusted-domain.com")
                .addStatement("$T source = new $T()", urlBasedCorsClass, urlBasedCorsClass)
                .addStatement("source.registerCorsConfiguration($S, config)", "/**")
                .addStatement("return source")
                .build();

        TypeSpec securityConfigClass = TypeSpec.classBuilder(className + "PolicyConfig")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(configurationClass)
                .addMethod(corsBeanMethod)
                .build();

        JavaFile javaFile = JavaFile.builder(packageName + ".security", securityConfigClass)
                .indent("    ")
                .build();

        javaFile.writeTo(filer);
    }
}