package es.ucm.fdi.tfg.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import es.ucm.fdi.tfg.analyzer.annotations.SecurifyScan;

@SecurifyScan(policy = "REST_STRICT") // Protección programática exigida por el Gatekeeper
//@RestController
public class UnprotectedController {

    @GetMapping("/api/vulnerable-data")
    public String getSensitiveData() {
        return "Información sin securizar";
    }
}