package es.ucm.fdi.tfg.analyzer.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Automatiza el control de acceso a nivel de método basándose en reglas ACL.
 */
@Retention(RetentionPolicy.SOURCE) // Solo en tiempo de compilación
@Target(ElementType.METHOD)
public @interface GeneratePreAuthorize {
    String roleSource() default "";
}