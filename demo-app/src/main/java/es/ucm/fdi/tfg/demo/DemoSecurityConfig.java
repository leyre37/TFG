package es.ucm.fdi.tfg.demo;

import es.ucm.fdi.tfg.analyzer.annotations.AutoSecureEndpoint;
import es.ucm.fdi.tfg.analyzer.annotations.AutoCorsConfig;
import es.ucm.fdi.tfg.analyzer.annotations.EnforceCsrf;
import es.ucm.fdi.tfg.analyzer.annotations.InjectSecurityPolicy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import java.security.MessageDigest;
import java.util.Random;

@Configuration
@EnableWebSecurity
// 1. Política General
@AutoSecureEndpoint(policy = "REST_STRICT")
// 2. Inyección de política estricta de CORS
@AutoCorsConfig(origins = {"https://trusted-domain.com", "https://mi-empresa.com"})
// 3. Protección CSRF forzada para endpoints que modifican estado
@EnforceCsrf(methods = {"POST", "PUT", "DELETE"})
// 4. Inyección de política de seguridad global desde YAML
@InjectSecurityPolicy(source = "security-policies.yml")
public class DemoSecurityConfig {

    // 1. SEC-SECRET-001: Secretos en código
    private String dbPassword = "root_password_2024";
    private String googleApiKey = "AIzaSyB-v3X9xLz0Q";

    // 2. SEC-NET-001: Protocolo inseguro
    private String updateUrl = "http://miservidor.com";

    // 3. SEC-CRYPTO-002: Generador aleatorio predecible
    private Random rnd = new Random();

    // 4. SEC-PWD-001: PasswordEncoder inseguro
    @Bean
    public Object insecureEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    // 5. SEC-PWD-001: Algoritmo de hash roto (MD5)
    public void hashTest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }

    // 6. SEC-CORS-001: CORS mal configurado (Wildcard + Credentials)
    public void corsConfiguration() {
        org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
        config.addAllowedOrigin("*");
        config.setAllowCredentials(true);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // 7. SEC-AUTH-001: PermitAll en método de escritura (POST)
                        .requestMatchers(HttpMethod.POST, "/api/admin/**").permitAll()
                        .anyRequest().authenticated()
                )
                // 8. SPRING-SEC-001: CSRF desactivado
                .csrf(csrf -> csrf.disable())

                // 9. SEC-HEAD-001: Cabeceras de seguridad desactivadas (Falta CSP y FrameOptions)
                .headers(headers -> headers.disable());

        return http.build();
    }
}