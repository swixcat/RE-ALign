# RE-ALign
Modern binary tools often rely on disassembler to transform raw binary
data into assembly code. Linear sweep algorithm is one of the most used
technique in this case. However, it is vulnerable to misalignment. Through
this project, our goal was to conduct an experiment on 64-bit and 32-bit
benign and non-obfuscated binaries by choosing randomly an offset as entry
point and to see after how many instructions there will be a realignment or
an invalid output.


## Description
`"./Report.pdf"   : It is the report of the project.`

`"./code"         : It contains "main.py" and "ExportInstructionsToCSV.java" that were used for the experiment.`

`"./csv_bin"      : It contains all the csv the files generated from the binaries used for the experiment.`

`"./result_dir"   : It contains all the plots generated from the experiment in "png" format.`

`"./journal.txt"  : It contains a trace of all the results of each binary. The informations there can be reused (for instance to have different representation of the result...).`



## How to use
Given a binary file, if you want to extract its (offset, instruction) easily, you should include "./code/ExportInstructionsToCSV.java" file in the "./ghidra/support/analyzeHeadless" of the ghidra folder in your PC. Then, complete the "configuration" part of the file "./code/main.py" and run it.
