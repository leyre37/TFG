package es.ucm.fdi.tfg.analyzer.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.PARAMETER) // Solo se aplica a Parámetros de métodos
public @interface SensitiveParam {
    // Permite pasar patrones
    String[] patterns() default {};
}