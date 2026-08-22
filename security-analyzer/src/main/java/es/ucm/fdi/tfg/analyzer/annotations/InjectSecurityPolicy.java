package es.ucm.fdi.tfg.analyzer.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotación para inyectar políticas de seguridad globales desde un archivo YAML.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.SOURCE) // Solo en tiempo de compilación
public @interface InjectSecurityPolicy {
    String source() default "security-policies.yml";
}