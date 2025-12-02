!start.

+!start[_]
    <- .print("Scanner agent started");
       scanProject("/mnt/c/Users/rakib/Documents/Essai/C_Code").
+vulnerabilityFound(File, Info)
    <- .print("[CRITICAL] Potential Vulnerability discovered in ", File, ": ", Info).