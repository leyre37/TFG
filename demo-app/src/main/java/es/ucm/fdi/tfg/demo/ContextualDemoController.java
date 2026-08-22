package es.ucm.fdi.tfg.demo;

import es.ucm.fdi.tfg.analyzer.annotations.EnforceInputValidation;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class ContextualDemoController {

    @EnforceInputValidation
    @PostMapping("/api/contact")
    public String sendContactMessage(@RequestParam String userEmail, @RequestParam String message) {
        return "Mensaje enviado a: " + userEmail;
    }

    @EnforceInputValidation
    @PostMapping("/api/ping")
    public String pingSystem(@RequestParam String ipAddress) {
        return "Ping realizado a la IP: " + ipAddress;
    }
}