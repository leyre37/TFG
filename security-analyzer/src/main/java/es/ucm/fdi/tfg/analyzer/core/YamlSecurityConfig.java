package es.ucm.fdi.tfg.analyzer.core;

import java.util.Map;

/**
 * Modelo de datos para mapear el archivo security-policies.yml
 */
public class YamlSecurityConfig {

    // Mapea la clave principal "policies" del YAML
    public Map<String, PolicyDetail> policies;

    public static class PolicyDetail {
        public String access;     //ejemplo: "hasRole('PAYMENT_ADMIN')"
        public String csrf;       //ejemplo: "required"
        public CorsPolicy cors;   //Sub-nodo para CORS
        public Map<String, String> headers; //Para inyección de cabeceras
    }

    public static class CorsPolicy {
        public String allowed_origins; //ejemplo: "https://trusted-domain.com"
        public String mode;            //ejemplo: "strict"
    }
}