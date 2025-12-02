import jason.infra.local.RunLocalMAS;
import jason.mas2j.MAS2JProject;
import jason.mas2j.AgentParameters;
import jason.mas2j.ClassParameters;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MainProgrammaticMAS {
    public static void main(String[] args) throws Exception {
        System.setProperty("jason.webmindinspector.host", "0.0.0.0");

        MAS2JProject project = new MAS2JProject();

        project.setInfrastructure(new ClassParameters("jason.infra.local.RunLocalMAS"));

        ClassParameters envClass = new ClassParameters();
        envClass.setClassName("jason.env.ScanEnvironment");
        project.setEnvClass(envClass);

        AgentParameters scanner = new AgentParameters();
        scanner.name = "scanner";
        scanner.setAgClass("jason.asSemantics.Agent"); // Jason 3.3 agent class
        scanner.setNbInstances(1);
        scanner.setSource("agents/scanner.asl");
        System.out.println("ASL file" + scanner.getSourceAsFile().toString() +" exist ?: "+ Files.exists(Paths.get("agents/scanner.asl")) +" is Dir ?:  " +Files.isDirectory(Paths.get("agents/scanner.asl")));
        project.addAgent(scanner);
        System.out.println("Project : " + project.toString()); 
        RunLocalMAS runner = new RunLocalMAS();
        runner.setProject(project);

        runner.create();
        System.out.println("[DEBUG] Resolved agent .asl path = " +  scanner.getSourceAsFile().getAbsolutePath());


        runner.start();
    }
}