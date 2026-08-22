package es.ucm.fdi.tfg.analyzer.core;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.File;

public class PolicyLoader {

    public static PolicyConfig load(String path) throws Exception {
        PolicyConfig config = new PolicyConfig();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new File(path));
        doc.getDocumentElement().normalize();

        // 1. CARGAR REGLAS JAVA (Detección por Reflexión)
        NodeList ruleList = doc.getElementsByTagName("rule");
        for (int i = 0; i < ruleList.getLength(); i++) {
            Element el = (Element) ruleList.item(i);
            String id = el.getAttribute("id");
            String name = el.getAttribute("name");
            boolean active = Boolean.parseBoolean(el.getAttribute("active"));
            Finding.Severity severity = Finding.Severity.valueOf(el.getAttribute("severity"));

            config.ruleMap.put(id, new PolicyConfig.RuleSettings(name, active, severity));
        }

        // 2. CARGAR COMPONENTES VULNERABLES (Análisis SCA/CVE)
        NodeList compList = doc.getElementsByTagName("component");
        for (int i = 0; i < compList.getLength(); i++) {
            Element el = (Element) compList.item(i);
            config.vulnerableComponents.add(new PolicyConfig.VulnerableComponent(
                    el.getAttribute("artifact"),
                    el.getAttribute("version"),
                    el.getAttribute("cve"),
                    el.getAttribute("severity"),
                    "Actualizar el componente " + el.getAttribute("artifact") + " a una versión superior a la " + el.getAttribute("version")
            ));
        }

        // 3. CARGAR CATÁLOGO DE ROLES PERMITIDOS (Para reglas SpEL/RBAC)
        NodeList rolesNode = doc.getElementsByTagName("allowed-roles");
        if (rolesNode.getLength() > 0) {
            String rolesText = rolesNode.item(0).getTextContent();
            if (rolesText != null && !rolesText.isEmpty()) {
                for (String r : rolesText.split(",")) {
                    config.allowedRoles.add(r.trim());
                }
            }
        }

        NodeList severityNode = doc.getElementsByTagName("fail-on-severity");
        if (severityNode.getLength() > 0) {
            String sevText = severityNode.item(0).getTextContent().trim();
            config.failOnSeverity = Finding.Severity.valueOf(sevText);
        }

        return config;
    }
}
