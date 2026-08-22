package es.ucm.fdi.tfg.analyzer.core;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class YamlPolicyLoader {

    public static YamlSecurityConfig load(Path yamlPath) throws Exception {

        LoaderOptions options = new LoaderOptions();

        //Pasamos tanto la clase como las opciones al constructor
        Yaml yaml = new Yaml(new Constructor(YamlSecurityConfig.class, options));

        try (InputStream in = Files.newInputStream(yamlPath)) {
            return yaml.load(in);
        }
    }
}