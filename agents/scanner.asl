//!start.

//+!start[_]
//    <- .print("Scanner agent started");
//       scanProject("/mnt/C_Code").

//+vulnerabilityFound(File, Info)
//    <- .print("[CRITICAL] Potential Vulnerability discovered in ", File, ": ", Info).


+!start <-
    !prepare_scan;
    !scan_project;
    !generate_report.


+!prepare_scan <-
    !request_project_path.
    !verify_project_exists(ProjectPath).
    !collect_C_files(ProjectPath).
    !check_can_we_read_the_C_files(C_Files).

+!scan_project <-
    !extract_FunctionsInfos(C_Files). //should extract functions with start, end line number, list of vars, however we extract the infos where there is a use of an unsafe functions
    !perform_analysis(Extracted_Fun, C_Files). //is there a potential risk that there's an actual vuln before proceeding to test for a security vulnerability , could it be integer/string or heap overflow, probabably a use after free
    !run_security_tests(Analysed_Ext_Fun, C_files); //here we test for the postivity of the vulnerability if not , we remove it from our perception, no need to know anything about it
    !summarize_results   //summarize the results, signal that we percieved that the found functions are vulnerable and these are not vulnerable, however we need to load the other functions too if there's a call made to made them

+!run_security_tests(Analysed_Ext_Fun, C_files) <-
    forall Analysed_Ext_Fun in Functions {
        !test_for_integer_buffer_overflow(Analysed_Ext_Fun)
        !test_for_string_buffer_overflow(Analysed_Ext_Fun)
        !test_for_unchecked_return_values(Analysed_Ext_Fun)
        !test_for_insecure_functions(Analysed_Ext_Fun)
    }.
