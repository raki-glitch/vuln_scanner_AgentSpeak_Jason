//-----------------------------------------
// START
//-----------------------------------------
+!start <-
    .print("Scanner agent started");
    !request_project_path.

//-----------------------------------------
// REQUEST PROJECT PATH FROM ENVIRONMENT
//-----------------------------------------
+!request_project_path <-
    .print("Requesting project path from environment").

//-----------------------------------------
// ENVIRONMENT REPLY: PROJECT PATH PROVIDED
//-----------------------------------------
+project_path(NewPath) <-
    -current_project_path(_);
    +current_project_path(NewPath);
    .print("Updated project path to: ", NewPath);
    !prepare_scan(NewPath).

//-----------------------------------------
// ENVIRONMENT REPLY: NO PROJECT PATH
//-----------------------------------------
+no_project_path_available <-
    -no_project_path_available;
    .print("No project path found. Retrying...");
    .wait(2000);
    !request_project_path.

//-----------------------------------------
// PREPARE SCAN
//-----------------------------------------
+!prepare_scan(ProjectPath) <-
    .print("Preparing scan for: ", ProjectPath);
    !verify_project_exists(ProjectPath);
    !collect_C_files(ProjectPath);
    !check_can_we_read_the_C_files(C_Files);
    !scan_project.

//-----------------------------------------
// VERIFY PROJECT DIRECTORY
//-----------------------------------------
+!verify_project_exists(ProjectPath) <-
    .print("Verifying project path: ", ProjectPath).

+project_exists(ProjectPath) <-
    .print("Project directory verified: ", ProjectPath);
    !collect_C_files(ProjectPath).

+project_not_found(ProjectPath) <-
    -project_not_found;
    .print("Project directory does not exist: ", ProjectPath);
    .wait(2000);
    !request_project_path.

//-----------------------------------------
// COLLECT C FILES
//-----------------------------------------
+!collect_C_files(ProjectPath) <-
    .print("Requesting environment to collect C files from: ", ProjectPath).

+c_file(FilePath) <-
    .print("Collected C file: ", FilePath).

//-----------------------------------------
// CHECK READABILITY OF C FILES
//-----------------------------------------
+!check_can_we_read_the_C_files(C_Files) <-
    .print("Checking readability of collected C files...");
    !check_readability_action(C_Files).

+!check_readability_action(C_Files) <-
    .print("Delegating readability check to environment...").

+file_readable(FilePath) <-
    .print("File is readable: ", FilePath);
    +readable_file(FilePath).

+file_skip_analysis(FilePath) <-
    .print("File is NOT readable, skipping: ", FilePath);
    +skipped_file(FilePath).

//-----------------------------------------
// SCAN PROJECT
//-----------------------------------------
+!scan_project <-
    !extract_FunctionsInfos(C_Files);
    !perform_analysis;
    !run_security_tests(Analysed_Ext_Fun, C_Files);
    !summarize_results;
    !generate_report.

//-----------------------------------------
// EXTRACT FUNCTION INFOS
//-----------------------------------------
+!extract_FunctionsInfos <- 
    .print("Extracting function information from readable C files...");
    forall File in readable_file(FilePath) {
        !extract_functions(File);
    }.

//-----------------------------------------
// PERFORM ANALYSIS TO DETECT POTENTIAL RISKS
//-----------------------------------------
+!perform_analysis <-
    .print("Performing analysis on extracted functions...");

    forall Function, File, Start, End, Vars, Ops, Calls in function_info(Function, File, Start, End, Vars, Ops, Calls) {

        // Parse variable info: Vars format -> {varName:type:size,...}
        forall VarInfo in Vars {
            VarInfo = VarInfo.replace("{","").replace("}","");
            VarInfoList = split(VarInfo,",");  // split individual var:type:size

            forall V in VarInfoList {
                Parts = split(V,":");
                VarName = Parts[0];
                VarType = Parts[1];
                VarSize = number(Parts[2]);

                // Record variables with types and sizes
                if (VarType == "char") {
                    +buffer_variable(Function, VarName, VarSize);
                }
                else if (VarType == "int") {
                    +int_variable(Function, VarName, VarSize);
                }
            }
        }

        // Map each unsafe function to its corresponding potential risk
        forall UnsafeFunc in Ops {
            if (UnsafeFunc == "gets") {
                +potential_risk(Function, "unchecked_input");
            }
            else if (UnsafeFunc == "strcpy" || UnsafeFunc == "strcat" || UnsafeFunc == "sprintf" || UnsafeFunc == "vsprintf" || UnsafeFunc == "strncpy" || UnsafeFunc == "strncat") {
                +potential_risk(Function, "string_buffer_overflow");
                // Link affected buffers
                forall B in buffer_variable(Function, BufName, BufSize) {
                    +buffer_overflow_risk(Function, BufName, BufSize, UnsafeFunc);
                }
            }
            else if (UnsafeFunc == "memcpy" || UnsafeFunc == "memmove" || UnsafeFunc == "bcopy") {
                +potential_risk(Function, "memory_corruption");
            }
            else if (UnsafeFunc == "scanf" || UnsafeFunc == "fscanf" || UnsafeFunc == "sscanf") {
                +potential_risk(Function, "unchecked_input");
                forall I in int_variable(Function, VarName, VarSize) {
                    +int_overflow_risk(Function, VarName, VarSize, UnsafeFunc);
                }
            }
            else if (UnsafeFunc == "printf" || UnsafeFunc == "fprintf" || UnsafeFunc == "snprintf" || UnsafeFunc == "vprintf" || UnsafeFunc == "vsnprintf") {
                +potential_risk(Function, "format_string");
            }
            else if (UnsafeFunc == "system" || UnsafeFunc == "popen" || UnsafeFunc.startsWith("exec")) {
                +potential_risk(Function, "command_injection");
            }
            else if (UnsafeFunc == "tmpnam" || UnsafeFunc == "tmpfile" || UnsafeFunc == "tempnam" || UnsafeFunc == "mktemp") {
                +potential_risk(Function, "insecure_temp_file");
            }
            else if (UnsafeFunc == "recv" || UnsafeFunc == "recvfrom") {
                +potential_risk(Function, "network_input_risk");
            }
            else if (UnsafeFunc == "malloc" || UnsafeFunc == "calloc" || UnsafeFunc == "realloc" || UnsafeFunc == "alloca") {
                +potential_risk(Function, "heap_issue");
            }
            else if (UnsafeFunc == "strdup" || UnsafeFunc == "strndup") {
                +potential_risk(Function, "memory_leak");
            }
        }

        // Propagate risks from called functions
        forall CalledFunc in Calls {
            if potential_risk(CalledFunc, Risk) {
                +potential_risk(Function, Risk);
            }
        }
    }.


//-----------------------------------------
// SECURITY TESTS (Placeholder)
//-----------------------------------------
//-----------------------------------------
// SECURITY TESTS
//-----------------------------------------
+!run_security_tests <-
    .print("Running security tests based on analysis...");

    // Test for string buffer overflows
    forall Function, BufName, BufSize, UnsafeFunc in buffer_overflow_risk(Function, BufName, BufSize, UnsafeFunc) {
        .print("Testing buffer overflow in function: ", Function, ", buffer: ", BufName, ", unsafe call: ", UnsafeFunc);
        !test_for_string_buffer_overflow(Function, BufName, BufSize, UnsafeFunc);
    }

    // Test for integer overflows or unchecked inputs
    forall Function, VarName, VarSize, UnsafeFunc in int_overflow_risk(Function, VarName, VarSize, UnsafeFunc) {
        .print("Testing integer overflow in function: ", Function, ", variable: ", VarName, ", unsafe call: ", UnsafeFunc);
        !test_for_integer_buffer_overflow(Function, VarName, VarSize, UnsafeFunc);
    }

    // Test for format string vulnerabilities
    forall Function, Risk in potential_risk(Function, "format_string") {
        .print("Testing format string vulnerability in function: ", Function);
        !test_for_format_string(Function);
    }

    // Test for command injection
    forall Function, Risk in potential_risk(Function, "command_injection") {
        .print("Testing command injection in function: ", Function);
        !test_for_command_injection(Function);
    }

    // Test for memory leaks / heap issues
    forall Function, Risk in potential_risk(Function, "heap_issue") {
        .print("Testing heap issues in function: ", Function);
        !test_for_heap_issue(Function);
    }

    forall Function, Risk in potential_risk(Function, "memory_leak") {
        .print("Testing memory leak in function: ", Function);
        !test_for_memory_leak(Function);
    }

    // Test for unsafe temp file usage
    forall Function, Risk in potential_risk(Function, "insecure_temp_file") {
        .print("Testing insecure temp file usage in function: ", Function);
        !test_for_insecure_temp_file(Function);
    }

    // Test for unchecked inputs
    forall Function, Risk in potential_risk(Function, "unchecked_input") {
        .print("Testing unchecked input in function: ", Function);
        !test_for_unchecked_input(Function);
    }

    // Test for network input risks
    forall Function, Risk in potential_risk(Function, "network_input_risk") {
        .print("Testing network input risks in function: ", Function);
        !test_for_network_input(Function);
    }

    .print("All applicable security tests executed.");
