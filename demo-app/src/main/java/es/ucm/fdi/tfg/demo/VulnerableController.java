package es.ucm.fdi.tfg.demo;

import es.ucm.fdi.tfg.analyzer.annotations.*;

import org.springframework.web.bind.annotation.*;
import es.ucm.fdi.tfg.analyzer.annotations.SecurifyScan;
import java.io.IOException;

@SecurifyScan(policy = "REST_STRICT")
@RestController
public class VulnerableController {

    // ---------------------------------------------------------
    // BLOQUE 1: PRUEBAS PARA EL ESCÁNER AST (Detección pasiva)
    // ---------------------------------------------------------

    // 1. Detección de Comando (SEC-INJ-001)
    @GetMapping("/exec")
    public void run(@RequestParam String cmd) throws java.io.IOException {
        Runtime.getRuntime().exec(cmd);
    }

    // 2. Detección de SQL (SEC-INJ-002)
    @GetMapping("/sql")
    public void query(@RequestParam String id) {
        String sql = "SELECT * FROM users WHERE id = " + id; // El '+' es clave
        System.out.println("Ejecutando: " + sql);
    }

    // 3. Detección de XSS (SEC-INJ-003)
    @GetMapping("/xss")
    public String vuela(@RequestParam String input) {
        return "Hola " + input; // El '+' es clave
    }

    // ---------------------------------------------------------
    // BLOQUE 2: PRUEBAS PARA EL AUTO-HARDENING (Red y Privacidad)
    // ---------------------------------------------------------

    // 4. Detección de Parámetro Sensible para Enmascaramiento (GDPR)
    @PostMapping("/api/pago")
    public String processPayment(@SensitiveParam @RequestParam String creditCard) {
        return "Procesando pago con tarjeta: " + creditCard;
    }

    // ---------------------------------------------------------
    // BLOQUE 3: PRUEBAS DE LÓGICA AVANZADA (Fase 11)
    // ---------------------------------------------------------

    // 5. Endpoint blindado con ACL, Validación y Auditoría
    @AclScan(role = "ROLE_ADMIN")
    @ValidateInput(type = "EMAIL")
    @AuditConfig(action = "MODIFICAR_USUARIO")
    @PostMapping("/api/admin/update")
    public String updateAdminData(@RequestParam String email) {
        // Antes de que Spring Boot llegue a ejecutar esta línea de código,
        // el framework, mediante el Aspecto generado en tiempo de compilación, habrá:
        // 1. Auditado la petición en el log (GDPR).
        // 2. Comprobado que el usuario autenticado tiene el rol "ROLE_ADMIN".
        // 3. Validado mediante RegEx que el parámetro 'email' tiene formato válido de correo.

        return "Datos actualizados correctamente para el correo: " + email;
    }

    // ---------------------------------------------------------
    // BLOQUE 4: PRUEBAS DE NUEVAS ANOTACIONES (Fase Final)
    // ---------------------------------------------------------

    // 6. Prueba de AutoDataMasking (Genera Aspecto AOP para ofuscar en runtime)
    @AutoDataMasking(fields = {"dni", "tarjeta"})
    @PostMapping("/api/registro")
    public String registrarUsuario(@RequestParam String dni, @RequestParam String tarjeta) {
        return "Usuario registrado correctamente con DNI: " + dni;
    }

    // 7. Prueba de EnforceInputValidation (Reescribe el AST inyectando @Email y @Valid)
    @EnforceInputValidation
    @PostMapping("/api/suscripcion")
    public String suscribirBoletin(@RequestParam String userEmail) {
        return "Suscripción completada para: " + userEmail;
    }
}