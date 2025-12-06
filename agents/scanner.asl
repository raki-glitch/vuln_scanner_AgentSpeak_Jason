+!start <-
    .print("Scanner agent started");
    !request_project_path.

+!request_project_path <-
    .print("Requesting project path from environment").  // environment handles action

+project_path(NewPath) <-
    -current_project_path(_);
    +current_project_path(NewPath);
    .print("Updated project path to: ", NewPath);
    !prepare_scan(NewPath).

+no_project_path_available <-
    -no_project_path_available;
    .print("No project path found. Retrying...");
    .wait(2000);
    !request_project_path.

+!prepare_scan(ProjectPath) <-
    .print("Preparing scan for: ", ProjectPath);
    !verify_project_exists(ProjectPath);
    !collect_C_files(ProjectPath);
    !check_can_we_read_the_C_files(C_Files);
    !scan_project.

+!verify_project_exists(ProjectPath) <-
    .print("Verifying project path: ", ProjectPath).  // environment handles action

+project_exists(ProjectPath) <-
    .print("Project directory verified: ", ProjectPath);
    !collect_C_files(ProjectPath).

+project_not_found(ProjectPath) <-
    -project_not_found;
    .print("Project directory does not exist: ", ProjectPath);
    .wait(2000);
    !request_project_path.

//Collecting 
+!collect_C_files(ProjectPath) <- //collect C Files
    .print("Requesting environment to collect C files from: ", ProjectPath).

+c_file(FilePath) <-
    .print("Collected C file: ", FilePath);

//check read C File
+!check_can_we_read_the_C_files(C_Files) <-
    .print("Checking readability of collected C files...");
    !check_readability_action(C_Files).

+file_readable(FilePath) <-
    .print("File is readable: ", FilePath).

+file_skip_analysis(FilePath) <-
    .print("File is NOT readable, skipping: ", FilePath).
    +skipped_file(FilePath).   // mark as skipped


//-----------------------------------------
// SCAN PROJECT
//-----------------------------------------
+!scan_project <-
    !extract_FunctionsInfos(C_Files);
    !perform_analysis(Extracted_Fun, C_Files);
    !run_security_tests(Analysed_Ext_Fun, C_Files);
    !summarize_results;
    !generate_report.

//extract functions Infos : 

+!extract_FunctionsInfos <-
    .print("Extracting functions from readable files...");
    forall File in readable_file(FilePath) {
        !extract_functions(File);
    }.

//-----------------------------------------
// SECURITY TESTS
//-----------------------------------------
//+!run_security_tests(Analysed_Ext_Fun, C_files) <-
//    forall Function in Analysed_Ext_Fun {
//        !test_for_integer_buffer_overflow(Function);
//        !test_for_string_buffer_overflow(Function);
//        !test_for_unchecked_return_values(Function);
//        !test_for_insecure_functions(Function)
//    }.
