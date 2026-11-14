// AnalyzeAVE2.java — Ghidra script to analyze AppleAVE2 kext for CVE-2026-84607
// Run in Ghidra's Script Manager after importing iOS 26.6.2 kernelcache
//
// Searches for:
// 1. AVE_HEVC_CheckVPSExtBounds (from our patch diff)
// 2. VPS-related functions (parse, check, validate)
// 3. The vps_max_layer_id consumer and its array access
// 4. IOKit userclient methods (SetSessionSettings etc)
// 5. DART mapping functions
//
// @category iOS
// @author jb-research

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class AnalyzeAVE2 extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== AppleAVE2 Analysis for CVE-2026-84607 ===");
        println("");

        // Phase 1: Find key functions by name
        println("--- Phase 1: Searching for key function names ---");
        String[] targets = {
            "AVE_HEVC_CheckVPS",
            "AVE_HEVC_ParseVPS",
            "CheckVPSExt",
            "vps_max_layer",
            "layer_id",
            "AlphaLayer",
            "SetSessionSettings",
            "AppleAVE2",
            "AVE_Client",
            "AVE_HEVC",
            "CheckMCTF",
            "Enqueue",
            "DeleteMemoryInfo",
            "IOSurfaceFromCSID",
            "statsMapBuffer",
            "memoryInfoCnt",
        };

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();

        for (String target : targets) {
            println("  Searching for: " + target);
            int count = 0;
            FunctionIterator fi = fm.getFunctions(true);
            while (fi.hasNext()) {
                Function f = fi.next();
                String name = f.getName();
                if (name.toLowerCase().contains(target.toLowerCase())) {
                    println("    FOUND: " + name + " @ " + f.getEntryPoint());
                    count++;
                    if (count > 10) {
                        println("    ... (more than 10 matches, truncated)");
                        break;
                    }
                }
            }
            if (count == 0) {
                println("    (no matches)");
            }
        }
        println("");

        // Phase 2: Search for key strings
        println("--- Phase 2: Searching for key strings ---");
        String[] strings = {
            "vps_max_layer_id",
            "layer_id_in_nuh",
            "AlphaLayerID",
            "RepFormatIndex",
            "dart-ave",
            "PTE invalid",
            "CheckVPSExtBounds",
            "vps_extension",
            "layer_idx",
            "num_rep_formats",
        };

        Memory mem = currentProgram.getMemory();
        for (String s : strings) {
            println("  Searching for string: \"" + s + "\"");
            Address addr = mem.findBytes(
                currentProgram.getMinAddress(),
                s.getBytes("UTF-8"),
                null, true, monitor);
            if (addr != null) {
                println("    FOUND @ " + addr);
                // Find xrefs to this string
                Reference[] refs = getReferencesTo(addr);
                for (int i = 0; i < Math.min(refs.length, 5); i++) {
                    Address from = refs[i].getFromAddress();
                    Function f = fm.getFunctionContaining(from);
                    String fname = f != null ? f.getName() : "(unknown)";
                    println("    Referenced from: " + from + " in " + fname);
                }
            } else {
                println("    (not found)");
            }
        }
        println("");

        // Phase 3: Look for the bounds check pattern
        println("--- Phase 3: Searching for bounds check patterns ---");
        println("  Looking for comparisons with 63 (0x3F) near VPS functions...");
        println("  (Manual inspection needed — check disassembly of found functions)");
        println("");

        // Phase 4: Find IOKit userclient external methods
        println("--- Phase 4: IOKit external method table ---");
        println("  Look for ::externalMethod or ::getTargetAndMethodForIndex");
        println("  Method 7 = SetSessionSettings (from SSD advisory, may differ on newer iOS)");
        println("");

        // Phase 5: Summary
        println("=== Analysis Complete ===");
        println("");
        println("NEXT STEPS:");
        println("1. Decompile any AVE_HEVC_CheckVPS* functions found above");
        println("2. Look for array accesses using vps_max_layer_id as index");
        println("3. Check if the index comes from VPS bitstream or IOKit config struct");
        println("4. Map the struct layout around the target array");
        println("5. Identify what's adjacent (heap corruption target)");
        println("");
        println("KEY QUESTION: Does the kernel use the 6-bit VPS bitstream value");
        println("(max OOB = 1 element) or the unclamped IOKit config struct value");
        println("(max OOB = 192 elements)?");
    }
}
