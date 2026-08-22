package es.ucm.fdi.tfg.demo.security.aspects;

import es.ucm.fdi.tfg.analyzer.core.DataMaskingService;
import java.lang.Object;
import java.lang.Throwable;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Configuration;

@Aspect
@Configuration
public class AutoMaskingAspect {
    @Around("@annotation(es.ucm.fdi.tfg.analyzer.annotations.AutoDataMasking)")
    public Object maskSensitiveData(ProceedingJoinPoint joinPoint) throws Throwable {
        Object[] args = joinPoint.getArgs();
        // Lógica generada para ofuscar parámetros de entrada
        for (int i = 0; i < args.length; i++) {
                    if (args[i] instanceof String) {
                        args[i] = DataMaskingService.mask((String)args[i]);
                    }
                };
        return joinPoint.proceed(args);
    }
}
