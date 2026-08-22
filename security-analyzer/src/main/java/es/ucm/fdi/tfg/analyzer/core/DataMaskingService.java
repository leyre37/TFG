package es.ucm.fdi.tfg.analyzer.core;

/**
 * Servicio encargado de ofuscar datos sensibles para evitar fugas en logs.
 */
public class DataMaskingService {

    public static String mask(String value) {
        if (value == null || value.length() < 4) {
            return "****"; // Valor por defecto para cadenas muy cortas
        }

        // Si parece un DNI (8 números + 1 letra)
        if (value.matches("\\d{8}[A-Za-z]")) {
            return "****" + value.substring(4);
        }

        // Si parece una tarjeta de crédito (16 dígitos) o cadena larga
        if (value.length() >= 12) {
            return "************" + value.substring(value.length() - 4);
        }

        // Enmascaramiento genérico: Ocultamos to-do menos los últimos 2 caracteres
        String asterisks = "*".repeat(value.length() - 2);
        return asterisks + value.substring(value.length() - 2);
    }
}