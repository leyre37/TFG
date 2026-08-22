package es.ucm.fdi.tfg.analyzer.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface EnforceCsrf {
    // Métodos HTTP que requerirán protección CSRF obligatoria
    String[] methods() default {"POST", "PUT", "DELETE"};
}