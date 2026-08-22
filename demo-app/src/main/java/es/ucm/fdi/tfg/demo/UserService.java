package es.ucm.fdi.tfg.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
// Importamos la nueva anotación de la Fase 4
import es.ucm.fdi.tfg.analyzer.annotations.GeneratePreAuthorize;

@Service
public class UserService {

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long id) {
        // Este está protegido
    }

    public void changeUserBalance(Long id, Double amount) {
        // Peligro: Este método es público y no tiene @PreAuthorize
    }

    @PreAuthorize("hasRole('ROLE_ADMN')") // Error tipográfico: ADMN en lugar de ADMIN
    public void deleteEverything() {}

    @PreAuthorize("permitAll()")
    public void publicAction() {}

    // ---------------------------------------------------------
    // Prueba de la Fase 4 (Políticas Avanzadas ACL dinámico)
    // ---------------------------------------------------------
    @GeneratePreAuthorize(roleSource = "Document::READ")
    public String getDocument(Long id) {
        return "Contenido confidencial del documento con ID: " + id;
    }
}