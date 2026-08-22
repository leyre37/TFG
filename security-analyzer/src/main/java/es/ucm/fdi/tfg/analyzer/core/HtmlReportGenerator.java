package es.ucm.fdi.tfg.analyzer.core;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Date;

public class HtmlReportGenerator {

    public static void generate(Path outputPath, List<Finding> findings) {
        long criticalCount = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count();
        long warningCount = findings.stream().filter(f -> f.getSeverity() == Finding.Severity.WARNING).count();

        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outputPath, StandardCharsets.UTF_8))) {
            writer.println("<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>");
            writer.println("<title>Auditoría de Seguridad TFG</title>");
            writer.println("<style>");
            writer.println("    :root { --critical: #e63946; --warning: #f4a261; --dark: #1a1f36; --bg: #f8fafc; }");
            writer.println("    body { font-family: sans-serif; margin: 0; background-color: var(--bg); color: #334155; }");
            writer.println("    .container { max-width: 1100px; margin: 40px auto; padding: 0 20px; }");
            writer.println("    .header { background: var(--dark); color: white; padding: 35px; border-radius: 16px; margin-bottom: 30px; text-align: center; }");
            writer.println("    .stats-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }");
            writer.println("    .stat-card { background: white; padding: 25px; border-radius: 16px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border-top: 5px solid #cbd5e1; }");
            writer.println("    .stat-card.critical { border-top-color: var(--critical); }");
            writer.println("    .stat-card.warning { border-top-color: var(--warning); }");
            writer.println("    .stat-num { font-size: 42px; font-weight: bold; display: block; margin-bottom: 5px; }");
            writer.println("    .stat-label { font-size: 13px; font-weight: 600; color: #64748b; text-transform: uppercase; }");

            // Estilo del Buscador
            writer.println("    .search-box { width: 100%; padding: 15px; margin-bottom: 20px; border-radius: 12px; border: 2px solid #ddd; font-size: 16px; box-sizing: border-box; outline: none; transition: border-color 0.3s; }");
            writer.println("    .search-box:focus { border-color: #007bff; }");

            writer.println("    table { width: 100%; border-collapse: separate; border-spacing: 0 12px; }");
            writer.println("    th { padding: 0 20px 10px; text-align: center; font-size: 12px; color: #94a3b8; text-transform: uppercase; }");
            writer.println("    td { background: white; padding: 25px 20px; border: none; vertical-align: middle; text-align: center; }");
            writer.println("    tr td:first-child { border-radius: 12px 0 0 12px; border-left: 6px solid #cbd5e1; font-weight: bold; }");
            writer.println("    tr td:last-child { border-radius: 0 12px 12px 0; }");
            writer.println("    tr.row-CRITICAL td:first-child { border-left-color: var(--critical); }");
            writer.println("    tr.row-WARNING td:first-child { border-left-color: var(--warning); }");
            writer.println("    .badge { padding: 6px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; color: white; text-transform: uppercase; }");
            writer.println("    .badge-CRITICAL { background: var(--critical); }");
            writer.println("    .badge-WARNING { background: var(--warning); }");
            writer.println("    pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 12px; margin-top: 10px; overflow-x: auto; text-align: left; }");
            writer.println("    .remed { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 15px; border-radius: 8px; font-size: 13px; margin-top: 15px; text-align: left; }");
            writer.println("</style></head><body>");

            writer.println("<div class='container'>");
            writer.println("<div class='header'><h1>Security Analysis Dashboard</h1><p>Proyecto: <strong>tfg-leyre</strong> | " + new Date() + "</p></div>");

            writer.println("<div class='stats-row'>");
            writer.println("    <div class='stat-card critical'><span class='stat-num' style='color:var(--critical)'>" + criticalCount + "</span><span class='stat-label'>Críticos</span></div>");
            writer.println("    <div class='stat-card warning'><span class='stat-num' style='color:var(--warning)'>" + warningCount + "</span><span class='stat-label'>Advertencias</span></div>");
            writer.println("    <div class='stat-card'><span class='stat-num'>" + findings.size() + "</span><span class='stat-label'>Total Hallazgos</span></div>");
            writer.println("</div>");

            // BUSCADOR HTML
            writer.println("<input type='text' id='searchInput' class='search-box' onkeyup='filterTable()' placeholder='Buscar por ID, archivo o descripción...'>");

            writer.println("<table id='findingsTable'><thead><tr><th>ID de Regla</th><th>Severidad</th><th>Ubicación</th><th>Detalle y Recomendación</th></tr></thead><tbody>");

            for (Finding f : findings) {
                writer.println("<tr class='row-" + f.getSeverity() + "'>");
                writer.println("    <td>" + f.getRuleId() + "</td>");
                writer.println("    <td><span class='badge badge-" + f.getSeverity() + "'>" + f.getSeverity() + "</span></td>");
                writer.println("    <td style='font-size: 13px; color: #64748b;'><strong>" + f.getFilePath() + "</strong><br>Línea " + f.getLineNumber() + "</td>");
                writer.println("    <td><div style='font-weight: 600; color: #1e293b; margin-bottom: 8px; text-align: left;'>" + f.getDescription() + "</div>");
                writer.println("        <div class='remed'><strong>Sugerencia de Remediación:</strong><br>" + f.getRemediation() + "</div></td>");
                writer.println("</tr>");
            }

            writer.println("</tbody></table></div>");

            // SCRIPT DE FILTRADO (JavaScript local)
            writer.println("<script>");
            writer.println("function filterTable() {");
            writer.println("    var input = document.getElementById('searchInput');");
            writer.println("    var filter = input.value.toUpperCase();");
            writer.println("    var table = document.getElementById('findingsTable');");
            writer.println("    var tr = table.getElementsByTagName('tr');");
            writer.println("    for (var i = 1; i < tr.length; i++) {");
            writer.println("        var text = tr[i].textContent || tr[i].innerText;");
            writer.println("        if (text.toUpperCase().indexOf(filter) > -1) {");
            writer.println("            tr[i].style.display = '';");
            writer.println("        } else {");
            writer.println("            tr[i].style.display = 'none';");
            writer.println("        }");
            writer.println("    }");
            writer.println("}");
            writer.println("</script>");

            writer.println("</body></html>");
        } catch (Exception e) { e.printStackTrace(); }
    }
}
