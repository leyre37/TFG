package es.ucm.fdi.tfg.analyzer.core;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class JsonReportGenerator {

    public static void generate(Path outputPath, List<Finding> findings) {
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8))) {
            writer.println("{");
            writer.println("  \"nombre_proyecto\": \"tfg-leyre\",");
            writer.println("  \"total_hallazgos\": " + findings.size() + ",");
            writer.println("  \"hallazgos\": [");

            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                writer.println("    {");
                writer.println("      \"id_regla\": \"" + f.getRuleId() + "\",");
                writer.println("      \"severidad\": \"" + f.getSeverity() + "\",");
                writer.println("      \"archivo\": \"" + f.getFilePath() + "\",");
                writer.println("      \"linea\": " + f.getLineNumber() + ",");
                writer.println("      \"descripcion\": \"" + f.getDescription().replace("\"", "\\\"") + "\",");
                writer.println("      \"remediacion\": \"" + f.getRemediation().replace("\"", "\\\"").replace("\n", " ") + "\"");
                writer.print("    }");
                if (i < findings.size() - 1) writer.println(",");
                else writer.println();
            }

            writer.println("  ]");
            writer.println("}");
        } catch (Exception e) {
            System.err.println("Error generando el reporte JSON: " + e.getMessage());
        }
    }
}
