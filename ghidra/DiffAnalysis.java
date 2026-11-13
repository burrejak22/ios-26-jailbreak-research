// Ghidra headless script: Decompile key functions for patch diffing
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript DiffAnalysis.java <target>
// Targets: jsc_type_confusion, webkit_type_confusion, imcore_messages, imageio_integer_overflow

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.*;
import java.util.*;

public class DiffAnalysis extends GhidraScript {

    // Target-specific function patterns for decompilation
    private static final Map<String, String[]> TARGETS = new HashMap<>();
    static {
        // CVE-2026-112659: WebKit/JSC type confusion
        TARGETS.put("jsc_type_confusion", new String[]{
            "AbstractInterpreter",
            "executeEffects",
            "executeEdges",
            "verifyEdge",
            "clobberize",
            "FixupPhase",
            "fixupNode",
            "SafeToExecute",
            "ConstantFolding",
            "StrengthReduction",
            "PredictionPropagation",
            "BackwardsPropagation",
            "filterType",
            "filterByValue",
            "speculationFromValue",
            "speculationFromJSType",
            "typeCheck",
            "checkArray"
        });

        // WebKit type confusion (WebCore side)
        TARGETS.put("webkit_type_confusion", new String[]{
            "toJSType",
            "toWrapped",
            "JSCast",
            "inherits",
            "classInfo",
            "visitChildren",
            "DownCast",
            "dynamicDowncast"
        });

        // CVE-2026-113960/113961: iMessage group chat
        TARGETS.put("imcore_messages", new String[]{
            "IMChat",
            "addParticipant",
            "removeParticipant",
            "joinChat",
            "leaveChat",
            "handleGroupChat",
            "groupParticipant",
            "messageHistory",
            "chatHistory",
            "authorization",
            "validateParticipant",
            "canJoin",
            "inviteRequired",
            "groupMembership",
            "IMGroupChat",
            "IMGroupAction"
        });

        // CVE-2026-64759: ImageIO integer overflow
        TARGETS.put("imageio_integer_overflow", new String[]{
            "CGImageSource",
            "ImageDecoder",
            "readImage",
            "decodeFrame",
            "allocateBuffer",
            "calculateSize",
            "imageSize",
            "bytesPerRow",
            "CGImageCreate",
            "ImageIO_",
            "kCGImageSource"
        });
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String target = args.length > 0 ? args[0] : "jsc_type_confusion";

        String[] patterns = TARGETS.get(target);
        if (patterns == null) {
            println("Unknown target: " + target);
            println("Available targets: " + String.join(", ", TARGETS.keySet()));
            return;
        }

        String outDir = "C:\\Users\\jmbur\\tools\\jb-research\\diffs";
        new File(outDir).mkdirs();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        decomp.setSimplificationStyle("decompile");

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int totalFunctions = 0;
        int matchedFunctions = 0;
        List<String> matchedNames = new ArrayList<>();

        String combinedFile = outDir + "\\" + target + "_decompiled.c";
        PrintWriter combined = new PrintWriter(new FileWriter(combinedFile));
        combined.println("// Target: " + target);
        combined.println("// Binary: " + currentProgram.getName());
        combined.println("// Generated: " + new Date());
        combined.println();

        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            totalFunctions++;
            String funcName = func.getName(true);

            boolean matches = false;
            for (String pattern : patterns) {
                if (funcName.contains(pattern)) {
                    matches = true;
                    break;
                }
            }

            if (matches) {
                matchedFunctions++;
                matchedNames.add(funcName + " @ " + func.getEntryPoint());

                DecompileResults results = decomp.decompileFunction(func, 120, monitor);
                if (results.decompileCompleted()) {
                    String decompiled = results.getDecompiledFunction().getC();
                    combined.println("// ============================================");
                    combined.println("// Function: " + funcName);
                    combined.println("// Address: " + func.getEntryPoint());
                    combined.println("// Size: " + func.getBody().getNumAddresses() + " bytes");
                    combined.println("// ============================================");
                    combined.println(decompiled);
                    combined.println();
                }
            }

            if (totalFunctions % 10000 == 0) {
                println("Processed " + totalFunctions + " functions, " + matchedFunctions + " matches...");
            }
        }

        combined.close();
        decomp.dispose();

        // Write index file
        String indexFile = outDir + "\\" + target + "_index.txt";
        PrintWriter index = new PrintWriter(new FileWriter(indexFile));
        index.println("Target: " + target);
        index.println("Binary: " + currentProgram.getName());
        index.println("Total functions: " + totalFunctions);
        index.println("Matched functions: " + matchedFunctions);
        index.println();
        for (String name : matchedNames) {
            index.println(name);
        }
        index.close();

        println("Done. " + matchedFunctions + " functions decompiled to " + combinedFile);
        println("Index written to " + indexFile);
    }
}
