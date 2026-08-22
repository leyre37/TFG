package es.ucm.fdi.tfg.demo.security;

import es.ucm.fdi.tfg.analyzer.annotations.SensitiveParam;
import es.ucm.fdi.tfg.analyzer.core.DataMaskingService;
import java.lang.Object;
import java.lang.Throwable;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

@Aspect
@Configuration
public class AutoMaskingLoggingAspect {
    private static final Logger logger = LoggerFactory.getLogger(AutoMaskingLoggingAspect.class);

    @Around("execution(* *(.., @es.ucm.fdi.tfg.analyzer.annotations.SensitiveParam (*), ..))")
    public Object maskAndLog(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Object[] args = joinPoint.getArgs();
        java.lang.annotation.Annotation[][] parameterAnnotations = signature.getMethod().getParameterAnnotations();

        for (int i = 0; i < args.length; i++) {
            for (java.lang.annotation.Annotation annotation : parameterAnnotations[i]) {
                if (annotation instanceof SensitiveParam) {
                    // Aplicamos ofuscación al argumento interceptado
                    String maskedValue = DataMaskingService.mask(String.valueOf(args[i]));
                    logger.info("TFG-SECURITY-AUDIT: Acceso a método '{}' con parámetro sensible ofuscado: {}", signature.getName(), maskedValue);
                }
            }
        }
        return joinPoint.proceed();
    }
}
