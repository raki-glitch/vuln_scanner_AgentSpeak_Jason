package jason.env;

import jason.asSyntax.*;
import java.util.stream.Stream;
import jason.environment.*;
import jason.asSyntax.parser.ParseException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.*;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.Path;
import java.nio.file.FileSystems;
import static java.nio.file.StandardWatchEventKinds.*;

public class ScanEnvironment extends Environment {
    private String lastKnownPath = null;
    private String folderToWatch = "src/CFiles";
    private WatchService watchService;
    private Thread watcherThread;

    // List of dangerous C functions
    private static final List<String> UNSAFE_FUNCS = Arrays.asList(
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "strncpy", "strncat",
        "memcpy", "memmove", "bcopy", "scanf", "fscanf", "sscanf", "printf",
        "fprintf", "snprintf", "vprintf", "vsnprintf", "system", "popen",
        "exec", "execl", "execlp", "execle", "execv", "execvp", "execve",
        "tmpnam", "tmpfile", "tempnam", "mktemp", "recv", "recvfrom",
        "malloc", "calloc", "realloc", "alloca", "strdup", "strndup"
    );

    @Override
    public void init(String[] args) {
        new Timer().scheduleAtFixedRate(new TimerTask() {
    @Override
    public void run() {
        System.out.println("Timer-2sec-Update Path");
        checkForPathUpdate();
    }
        }, 0, 60_000); // every 60 seconds

    }
    private void safeAddPercept(String literal) {
        try {
            addPercept(ASSyntax.parseLiteral(literal));
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    private void watchLoop() {
        while (true) {
            try {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    if (kind == OVERFLOW) continue;

                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();
                    File file = new File(folderToWatch, filename.toString());

                    if (file.isFile() && file.getName().endsWith(".c")) {
                        detectVulnerability(file);
                    }
                }
                key.reset();
            } catch (InterruptedException e) { return; }
        }
    }

    private void detectVulnerability(File file) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNum = 0;
            while ((line = br.readLine()) != null) {
                lineNum++;

                for (String func : UNSAFE_FUNCS) {
                    // Match whole word or function call
                    if (line.contains(func + "(") || line.matches(".*\b" + func + "\b.*")) {
                        String msg = func + " at line " + lineNum;

                        addPercept(Literal.parseLiteral(
                            "vulnerabilityFound(\"" + file.getAbsolutePath() + "\", \"" + msg + "\")"
                        ));

                        System.out.println("***[DEBUG] Percept added: " + msg);
                    }
                }
            }
        } catch (Exception e) { e.printStackTrace(); }
    }
    private void checkForPathUpdate() {
        String newPath = readPathFromWatchedFile();

        if (newPath == null) {
            System.out.println("checkForPathUpdate : No new path found recieved");
            safeAddPercept("no_project_path_available");
            return;
        }
        if (!newPath.equals(lastKnownPath)) {
            lastKnownPath = newPath;
            System.out.println("checkForPathUpdate : new path found recieved " + lastKnownPath);
            safeAddPercept("project_path(\"" + newPath + "\")");
        }
    }

    private String readPathFromWatchedFile() {
        try {
            Path file = Paths.get("/mnt/AgentInput/project_path.txt");

            if (!Files.exists(file)) {
                System.out.println("Please configure the file: /mnt/AgentInput/project_path.txt");
                return null;
            }

            String content = Files.readString(file).trim();
            return content.isEmpty() ? null : content;

        } catch (Exception e) {
            e.printStackTrace();
            return null;   // <- must return null in case of exception
        }
    }
    public boolean verifyProjectExists(String projectPath) {
        Path path = Paths.get(projectPath);
        return Files.exists(path) && Files.isDirectory(path);
    }
    private List<String> collectCFiles(String projectPath) {
    List<String> cFiles = new ArrayList<>();
    try (Stream<Path> paths = Files.walk(Paths.get(projectPath))) {
        paths.filter(Files::isRegularFile)
             .filter(p -> p.toString().endsWith(".c") || p.toString().endsWith(".h"))
             .forEach(p -> cFiles.add(p.toString()));
    } catch (IOException e) {
        e.printStackTrace();
    }
    return cFiles;
    }

    private List<String> extractFilesFromTerm(Term filesTerm) {
    List<String> files = new ArrayList<>();
    if(filesTerm.isList()) {
        for(Term t : ((ListTerm) filesTerm).getAsList()) {
            files.add(t.toString());
        }
    } else {
        files.add(filesTerm.toString());
    }
    return files;
}


    @Override
    public boolean executeAction(String agName, Structure action) {
        String ProjectPath;
        String C_Files;
        String Extracted_Fun;
        String functs;

        switch (action.getFunctor()) {
            case "request_project_path":
                checkForPathUpdate();
                break;
            case "verify_project_exists":
                if (action.getArity() >= 1) {
                    String projectPath = action.getTerm(0).toString();
                try {
                    if (verifyProjectExists(projectPath)) {
                        addPercept(ASSyntax.parseLiteral("project_exists(\"" + projectPath + "\")"));
                    } else {
                        addPercept(ASSyntax.parseLiteral("project_not_found(\"" + projectPath + "\")"));
                    }
                } catch (ParseException e) {
                    e.printStackTrace();
                }
                }
                break;

            case "collect_C_files":
            String projectPath = action.getTerm(0).toString();
            List<String> cFiles = collectCFiles(projectPath);

            try {
                // Send a percept with all C files to the agent
                for(String file : cFiles) {
                    addPercept(ASSyntax.parseLiteral("c_file(\"" + file + "\")"));
                }
            } catch (ParseException e) {
                e.printStackTrace();
            }
            break;
            case "check_readability_action":
                Term filesTerm = action.getTerm(0);
                List<String> files = extractFilesFromTerm(filesTerm);
                for(String filePath : files) {
                    Path path = Paths.get(filePath);
                    try {
                        if(Files.isReadable(path)) {
                            addPercept(ASSyntax.parseLiteral("file_readable(\"" + filePath + "\")"));
                        } else {
                            addPercept(ASSyntax.parseLiteral("file_skip_analysis(\"" + filePath + "\")"));
                        }
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                }
                break;
            // case "extract_FunctionsInfos":
            //     if (action.getArity() == 1) {
            //         C_Files = action.getTerm(0).toString();
            //     }
            //     extract_FunctionsInfos();
            // case "perform_analysis":
            //     if (action.getArity() == 2) {
            //         Extracted_Fun = action.getTerm(0).toString();
            //         C_Files = action.getTerm(1).toString();
            //     }
            //     perform_analysis();
            // case "test_for_integer_buffer_overflow":
            //     if (action.getArity() == 1) {
            //         functs = action.getTerm(0).toString();
            //     }
            //     test_for_integer_buffer_overflow();
                
            // case "test_for_string_buffer_overflow":
            //     if (action.getArity() == 1) {
            //         functs = action.getTerm(0).toString();
            //     }
            //     test_for_string_buffer_overflow();
            // case "test_for_unchecked_return_values":
            //     if (action.getArity() == 1) {
            //         functs = action.getTerm(0).toString();
            //     }
            //     test_for_unchecked_return_values();

            // case "test_for_insecure_functions":
            //     if (action.getArity() == 1) {
            //         functs = action.getTerm(0).toString();
            //     }
            //     test_for_insecure_functions();
            // default:
            //     System.out.println("Failed to get default Action");
        } 

/*         if (action.getFunctor().equals("scanProject")) {
            if (action.getArity() > 0) {
                folderToWatch = action.getTerm(0).toString().replace("\"", "");
            }
            File dir = new File(folderToWatch);
            try {
            watchService = FileSystems.getDefault().newWatchService();
            Path path = Paths.get(folderToWatch);
            System.out.println("[ENV] Not a test Env *Scanning file: " + path.toFile().getAbsolutePath());

            path.register(watchService, ENTRY_CREATE, ENTRY_MODIFY);

            watcherThread = new Thread(() -> watchLoop());
            watcherThread.setDaemon(true);
            watcherThread.start();

        } catch (IOException e) {
            e.printStackTrace();
        }
            if (dir.exists()) {
                for (File f : Objects.requireNonNull(dir.listFiles())) {
                    if (f.getName().endsWith(".c")) detectVulnerability(f);
                }
            }else{
                System.out.println(folderToWatch + "**** doesn\'t exist\n");
            }
            return true;
        }*/
        return true; 
    }
}