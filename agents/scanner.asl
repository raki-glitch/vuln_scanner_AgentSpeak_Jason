!start.

+!start[_]
    <- .print("Scanner agent started");
       scanProject("/mnt/C_Code").
+vulnerabilityFound(File, Info)
    <- .print("[CRITICAL] Potential Vulnerability discovered in ", File, ": ", Info).