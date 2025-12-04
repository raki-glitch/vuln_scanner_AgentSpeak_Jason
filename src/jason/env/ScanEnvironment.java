package jason.env;

import jason.asSyntax.*;
import jason.environment.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import static java.nio.file.StandardWatchEventKinds.*;

public class ScanEnvironment extends Environment {

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
        System.out.println("Init fun in env launched");
        
/*         try {
            watchService = FileSystems.getDefault().newWatchService();
            Path path = Paths.get(folderToWatch);
            System.out.println("[ENV] Scanning file: " + path.toFile().getAbsolutePath());

            path.register(watchService, ENTRY_CREATE, ENTRY_MODIFY);

            watcherThread = new Thread(() -> watchLoop());
            watcherThread.setDaemon(true);
            watcherThread.start();

        } catch (IOException e) {
            e.printStackTrace();
        }
 */    }

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

    @Override
    public boolean executeAction(String agName, Structure action) {
        if (action.getFunctor().equals("scanProject")) {
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
        }
        return false;
    }
}