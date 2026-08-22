package es.ucm.fdi.tfg.analyzer.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE) // Solo existe durante la compilación
@Target({ElementType.TYPE, ElementType.METHOD}) // Se aplica a Clases y Métodos
public @interface SecurifyScan {
    // Permite definir la política
    String policy() default "";
}