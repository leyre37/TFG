package es.ucm.fdi.tfg.analyzer.core;

import com.squareup.javapoet.*;

import javax.annotation.processing.Filer;
import javax.lang.model.element.Modifier;
import java.io.IOException;

public class MaskingCodeGenerator {

    public static void generateMaskingAspect(Filer filer) throws IOException {
        // 1. Clases de Spring AOP y Logging
        ClassName aspectClass = ClassName.get("org.aspectj.lang.annotation", "Aspect");
        ClassName configurationClass = ClassName.get("org.springframework.context.annotation", "Configuration");
        ClassName aroundClass = ClassName.get("org.aspectj.lang.annotation", "Around");
        ClassName proceedingJoinPointClass = ClassName.get("org.aspectj.lang", "ProceedingJoinPoint");
        ClassName methodSignatureClass = ClassName.get("org.aspectj.lang.reflect", "MethodSignature");

        ClassName loggerClass = ClassName.get("org.slf4j", "Logger");
        ClassName loggerFactoryClass = ClassName.get("org.slf4j", "LoggerFactory");

        // Referencia a nuestra anotación
        ClassName sensitiveParamClass = ClassName.get("es.ucm.fdi.tfg.analyzer.annotations", "SensitiveParam");
        // Referencia a nuestro servicio de enmascaramiento
        ClassName maskingServiceClass = ClassName.get("es.ucm.fdi.tfg.analyzer.core", "DataMaskingService");

        // 2. Crear el Logger estático
        FieldSpec loggerField = FieldSpec.builder(loggerClass, "logger")
                .addModifiers(Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
                .initializer("$T.getLogger(AutoMaskingLoggingAspect.class)", loggerFactoryClass)
                .build();

        // 3. Crear el método interceptor (@Around)
        MethodSpec.Builder interceptMethod = MethodSpec.methodBuilder("maskAndLog")
                .addModifiers(Modifier.PUBLIC)
                .addException(Throwable.class)
                .returns(Object.class)
                .addParameter(proceedingJoinPointClass, "joinPoint")
                // Intercepta cualquier método que tenga al menos un parámetro anotado con @SensitiveParam
                .addAnnotation(AnnotationSpec.builder(aroundClass)
                        .addMember("value", "\"execution(* *(.., @es.ucm.fdi.tfg.analyzer.annotations.SensitiveParam (*), ..))\"")
                        .build());

        // 4. Lógica de intercepción (Extraer parámetros, enmascarar y loggear)
        interceptMethod.addCode(
                "$T signature = ($T) joinPoint.getSignature();\n" +
                        "Object[] args = joinPoint.getArgs();\n" +
                        "java.lang.annotation.Annotation[][] parameterAnnotations = signature.getMethod().getParameterAnnotations();\n\n" +
                        "for (int i = 0; i < args.length; i++) {\n" +
                        "    for (java.lang.annotation.Annotation annotation : parameterAnnotations[i]) {\n" +
                        "        if (annotation instanceof $T) {\n" +
                        "            // Aplicamos ofuscación al argumento interceptado\n" +
                        "            String maskedValue = $T.mask(String.valueOf(args[i]));\n" +
                        "            logger.info(\"TFG-SECURITY-AUDIT: Acceso a método '{}' con parámetro sensible ofuscado: {}\", signature.getName(), maskedValue);\n" +
                        "        }\n" +
                        "    }\n" +
                        "}\n" +
                        "return joinPoint.proceed();\n",
                methodSignatureClass, methodSignatureClass, sensitiveParamClass, maskingServiceClass
        );

        // 5. Construir la clase final
        TypeSpec aspectConfigClass = TypeSpec.classBuilder("AutoMaskingLoggingAspect")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(aspectClass)
                .addAnnotation(configurationClass)
                .addField(loggerField)
                .addMethod(interceptMethod.build())
                .build();

        // 6. Escribir el archivo físico
        JavaFile javaFile = JavaFile.builder("es.ucm.fdi.tfg.demo.security", aspectConfigClass)
                .indent("    ")
                .build();

        javaFile.writeTo(filer);
    }

    // Lógica para @AutoDataMasking
    public static void generateAutoDataMaskingAspect(Filer filer, String packageName) throws IOException {
        ClassName aspectClass = ClassName.get("org.aspectj.lang.annotation", "Aspect");
        ClassName configurationClass = ClassName.get("org.springframework.context.annotation", "Configuration");
        ClassName aroundClass = ClassName.get("org.aspectj.lang.annotation", "Around");
        ClassName proceedingJoinPointClass = ClassName.get("org.aspectj.lang", "ProceedingJoinPoint");
        ClassName maskingServiceClass = ClassName.get("es.ucm.fdi.tfg.analyzer.core", "DataMaskingService");

        // 1. Crear el método interceptor (@Around) que reescribe los argumentos al vuelo
        MethodSpec aroundMethod = MethodSpec.methodBuilder("maskSensitiveData")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(AnnotationSpec.builder(aroundClass)
                        .addMember("value", "$S", "@annotation(es.ucm.fdi.tfg.analyzer.annotations.AutoDataMasking)")
                        .build())
                .returns(Object.class)
                .addException(Throwable.class)
                .addParameter(proceedingJoinPointClass, "joinPoint")
                .addStatement("$T[] args = joinPoint.getArgs()", Object.class)
                .addCode("// Lógica generada para ofuscar parámetros de entrada\n")
                .addStatement("for (int i = 0; i < args.length; i++) {\n" +
                        "    if (args[i] instanceof String) {\n" +
                        "        args[i] = $T.mask((String)args[i]);\n" +
                        "    }\n" +
                        "}", maskingServiceClass)
                .addStatement("return joinPoint.proceed(args)")
                .build();

        // 2. Crear la clase del Aspecto
        TypeSpec aspectClassType = TypeSpec.classBuilder("AutoMaskingAspect")
                .addModifiers(Modifier.PUBLIC)
                .addAnnotation(aspectClass)
                .addAnnotation(configurationClass)
                .addMethod(aroundMethod)
                .build();

        // 3. Escribir el archivo físico
        JavaFile javaFile = JavaFile.builder(packageName + ".security.aspects", aspectClassType)
                .indent("    ")
                .build();

        javaFile.writeTo(filer);
    }
}