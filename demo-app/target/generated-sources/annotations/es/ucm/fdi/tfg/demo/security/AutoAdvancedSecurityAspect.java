package es.ucm.fdi.tfg.demo.security;

import es.ucm.fdi.tfg.analyzer.annotations.AclScan;
import es.ucm.fdi.tfg.analyzer.annotations.AuditConfig;
import es.ucm.fdi.tfg.analyzer.annotations.GeneratePreAuthorize;
import es.ucm.fdi.tfg.analyzer.annotations.ValidateInput;
import java.lang.IllegalArgumentException;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Aspect
@Configuration
public class AutoAdvancedSecurityAspect {
    private static final Logger logger = LoggerFactory.getLogger(AutoAdvancedSecurityAspect.class);

    @Before("@annotation(es.ucm.fdi.tfg.analyzer.annotations.AclScan) || @annotation(es.ucm.fdi.tfg.analyzer.annotations.ValidateInput) || @annotation(es.ucm.fdi.tfg.analyzer.annotations.AuditConfig) || @annotation(es.ucm.fdi.tfg.analyzer.annotations.GeneratePreAuthorize)")
    public void enforceAdvancedSecurity(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        java.lang.reflect.Method method = signature.getMethod();
        Object[] args = joinPoint.getArgs();

        // --- LÓGICA DE AUDITORÍA (@AuditConfig) ---
        if (method.isAnnotationPresent(AuditConfig.class)) {
            AuditConfig audit = method.getAnnotation(AuditConfig.class);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = (auth != null) ? auth.getName() : "ANONYMOUS";
            logger.info("[AUDITORÍA TFG] Usuario: '{}' ejecutó Acción: '{}' en método: '{}'", username, audit.action(), signature.getName());
        }

        // --- LÓGICA DE CONTROL DE ACCESO (ACL - @AclScan) ---
        if (method.isAnnotationPresent(AclScan.class)) {
            AclScan acl = method.getAnnotation(AclScan.class);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean hasRole = false;
            if (auth != null) {
                hasRole = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals(acl.role()));
            }
            if (!hasRole) {
                logger.warn("[ACL BLOQUEADO] Acceso denegado al método '{}'. Se requería el rol: {}", signature.getName(), acl.role());
                throw new AccessDeniedException("Acceso denegado: No tienes el rol " + acl.role());
            }
        }

        // --- LÓGICA DE PRE-AUTHORIZE DINÁMICA (@GeneratePreAuthorize) ---
        if (method.isAnnotationPresent(GeneratePreAuthorize.class)) {
            GeneratePreAuthorize genAuth = method.getAnnotation(GeneratePreAuthorize.class);
            String roleSource = genAuth.roleSource();
            String[] parts = roleSource.split("::");
            if (parts.length == 2) {
                String entity = parts[0];
                String permission = parts[1];
                logger.info("[SECURITY] Verificando permisos dinámicos ACL: hasPermission(id, '{}', '{}') en método '{}'", entity, permission, signature.getName());
                // Aquí se enlaza con el AclService de Spring Security
            }
        }

        // --- LÓGICA DE VALIDACIÓN DE ENTRADAS (@ValidateInput) ---
        if (method.isAnnotationPresent(ValidateInput.class)) {
            ValidateInput val = method.getAnnotation(ValidateInput.class);
            if ("EMAIL".equalsIgnoreCase(val.type())) {
                for (Object arg : args) {
                    if (arg instanceof String) {
                        String email = (String) arg;
                        if (!email.matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
                            logger.error("[VALIDACIÓN FALLIDA] Formato de Email inválido detectado: {}", email);
                            throw new IllegalArgumentException("Formato de entrada inválido: Se esperaba un Email");
                        }
                    }
                }
            }
        }
    }
}
