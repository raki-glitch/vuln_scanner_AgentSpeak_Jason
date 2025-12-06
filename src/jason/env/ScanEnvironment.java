package jason.env;

import jason.asSyntax.*;
import jason.environment.*;
import jason.asSyntax.parser.ParseException;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

public class ScanEnvironment extends Environment {

    private String lastKnownPath = null;

    // List of unsafe C functions
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
        // nothing specific here for now
    }

    private void safeAddPercept(String literal) {
        try {
            addPercept(ASSyntax.parseLiteral(literal));
        } catch (ParseException e) {
            e.printStackTrace();
        }
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

    private void extractFunctionsFromFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.canRead()) {
            System.out.println("[ENV] Cannot read file: " + filePath);
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNum = 0;
            String currentFunc = null;
            int funcStart = 0;

            List<String> vars = new ArrayList<>();
            List<String> varTypes = new ArrayList<>();
            List<Integer> varSizes = new ArrayList<>();
            List<String> operations = new ArrayList<>();
            List<String> calls = new ArrayList<>();

            while ((line = br.readLine()) != null) {
                lineNum++;

                // Detect function definition
                if (line.matches(".*\\w+\\s+\\w+\\s*\\(.*\\).*\\{")) {
                    if (currentFunc != null) {
                        addFunctionInfoPercept(filePath, currentFunc, funcStart, lineNum-1,
                            vars, varTypes, varSizes, operations, calls);
                    }
                    currentFunc = line.replaceAll("\\(.*\\).*", "").trim().split("\\s+")[1];
                    funcStart = lineNum;

                    vars.clear();
                    varTypes.clear();
                    varSizes.clear();
                    operations.clear();
                    calls.clear();
                }

                // Detect variables with optional size
                // Examples: "int a;", "char buf[20];", "float nums[10];"
                if (line.matches(".*\\w+\\s+\\w+(\\[\\d+\\])?\\s*;.*")) {
                    String type = line.trim().split("\\s+")[0];
                    String namePart = line.trim().split("\\s+")[1];
                    String name = namePart.replaceAll("\\[.*\\]", "");
                    int size = 1;
                    if (namePart.contains("[")) {
                        size = Integer.parseInt(namePart.replaceAll(".*\\[(\\d+)\\].*", "$1"));
                    }

                    vars.add(name);
                    varTypes.add(type);
                    varSizes.add(size);
                }

                // Detect unsafe functions
                for (String unsafeFunc : UNSAFE_FUNCS) {
                    if (line.contains(unsafeFunc + "(")) {
                        operations.add(unsafeFunc);
                        addUnsafeFunctionPercept(unsafeFunc, currentFunc, lineNum);
                    }
                }

                // Detect function calls
                if (line.matches(".*\\w+\\(.*\\);.*")) {
                    String calledFunc = line.replaceAll("(\\w+)\\(.*\\);.*", "$1");
                    calls.add(calledFunc);
                }
            }

            // Add last function
            if (currentFunc != null) {
                addFunctionInfoPercept(filePath, currentFunc, funcStart, lineNum,
                    vars, varTypes, varSizes, operations, calls);
            }

        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }
    }


private void addFunctionInfoPercept(String filePath, String funcName, int startLine, int endLine,
                                   List<String> vars, List<String> varTypes, List<Integer> varSizes,
                                   List<String> operations, List<String> calls) throws ParseException {

        String varsStr = "{";
        for (int i = 0; i < vars.size(); i++) {
            varsStr += vars.get(i) + ":" + varTypes.get(i) + ":" + varSizes.get(i);
            if (i != vars.size() - 1) varsStr += ",";
        }
        varsStr += "}";

        String opsStr = operations.toString().replace("[","{").replace("]","}");
        String callsStr = calls.toString().replace("[","{").replace("]","}");

        String literal = String.format(
            "function_info(\"%s\", \"%s\", %d, %d, %s, %s, %s)",
            funcName, filePath, startLine, endLine, varsStr, opsStr, callsStr
        );
        addPercept(ASSyntax.parseLiteral(literal));
    }

    private void addUnsafeFunctionPercept(String unsafeFunc, String funcName, int lineNum) throws ParseException {
        String literal = String.format(
            "unsafe_function_used(\"%s\", \"%s\", %d)",
            unsafeFunc, funcName, lineNum
        );
        safeAddPercept(literal);
    }

    @Override
    public boolean executeAction(String agName, Structure action) {
        switch (action.getFunctor()) {
            case "collect_C_files": {
                String projectPath = action.getTerm(0).toString();
                List<String> cFiles = collectCFiles(projectPath);
                for (String file : cFiles) {
                    safeAddPercept("c_file(\"" + file + "\")");
                }
                break;
            }
            case "check_readability_action": {
                Term filesTerm = action.getTerm(0);
                List<String> files = new ArrayList<>();
                if (filesTerm.isList()) {
                    for (Term t : ((ListTerm) filesTerm).getAsList()) files.add(t.toString());
                } else {
                    files.add(filesTerm.toString());
                }

                for (String filePath : files) {
                    Path path = Paths.get(filePath);
                    try {
                        if (Files.isReadable(path)) {
                            safeAddPercept("file_readable(\"" + filePath + "\")");
                        } else {
                            safeAddPercept("file_skip_analysis(\"" + filePath + "\")");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                break;
            }
        }
        return true;
    }
}
