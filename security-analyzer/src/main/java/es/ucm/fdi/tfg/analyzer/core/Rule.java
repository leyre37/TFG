package es.ucm.fdi.tfg.analyzer.core;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public interface Rule {
    List<Finding> analyze(Path sourceFile) throws IOException;

    void setSettings(PolicyConfig.RuleSettings settings);

}
