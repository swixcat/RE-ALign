import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

public class ExportInstructionsToCSV extends GhidraScript {            // ExportInstructionsToCSV.java

    @Override
    public void run() {
        try {
            if (currentProgram == null) {
                printerr("No program loaded.");
                return;
            }

            if (currentProgram.getExecutablePath() == null) {
                printerr("Executable path not set.");
                return;
            }

            String[] args = getScriptArgs();
            if (args.length < 1) {
                printerr("Output CSV path not provided.");
                return;
            }

            String outputPath = args[0];
            println("Exporting to: " + outputPath);

            try (FileWriter writer = new FileWriter(outputPath)) {        // Ensure FileWriter is closed properly
                writer.write("Offset,Instruction\n");                    // Write CSV header

                Listing listing = currentProgram.getListing();          // Get the program's listing
                InstructionIterator instructions = listing.getInstructions(true);    // Get all instructions

                int count = 0;  // Initialize instruction count
                while (instructions.hasNext()) {      // Iterate through instructions
                    Instruction instr = instructions.next();    
                    String address = instr.getAddress().toString();  // Get instruction address
                    String mnemonic = instr.toString();        // Get instruction mnemonic
                    writer.write(address + "," + mnemonic + "\n");
                    count++;
                }

                println("Export completed. Total instructions: " + count);
            } catch (IOException ioex) {
                printerr("IO Error while writing CSV: " + ioex.getMessage());
                ioex.printStackTrace();
            } catch (Exception ex) {
                printerr("Unexpected error during export: " + ex.getMessage());
                ex.printStackTrace();
            }

        } catch (Exception topEx) {
            printerr("Fatal error in script: " + topEx.getMessage());
            topEx.printStackTrace();
        }
    }
}
