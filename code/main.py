import os
import csv
import random
import matplotlib.pyplot as plt
from capstone import *
from collections import defaultdict
import numpy as np
import subprocess
import struct


# Configuration
ORIG_BIN_PATH = "/home/swisscat/Desktop/REalign_proj/bigbins/busybox"   # ----CHANGE IT----       the binary file's path
BASE_CSV_DIR = "/home/swisscat/Desktop/REalign_proj/csv_bin"            # ----CHANGE IT----       directory where the CSV files will be stored
RESULTS_DIR = "/home/swisscat/Desktop/REalign_proj/result_dir"          # ----CHANGE IT----       directory where the results will be stored

NUM_TRIALS = 1000   # number of trials for each binary file 

GHIDRA_PATH = "/usr/share/ghidra/support/analyzeHeadless"               # ----CHANGE IT----       path to Ghidra's headless analyzer
PROJECT_DIR = "/tmp/ghidra_project"                                     #                         you should create a directory which will be used during bin2csv execution
SCRIPT_PATH = "/home/swisscat/ghidra_scripts/ExportInstructionsToCSV.java"  # ----CHANGE IT----   compiled Ghidra script

JOURNAL_FILE= "/home/swisscat/Desktop/REalign_proj/optim_files/journal.txt" # ----CHANGE IT----   file where the results will be stored



def detect_architecture(filepath):                      # detects the architecture and bitness of the binary file
    with open(filepath, 'rb') as f:
        magic = f.read(5)

        # ELF file
        if magic[:4] == b'\x7fELF':
            # 5th byte: 1 = 32-bit, 2 = 64-bit
            bitness = magic[4]
            return 'x86', 64 if bitness == 2 else 32
        
        # PE file (Windows executable)
        elif magic[:2] == b'MZ':
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_offset + 4)
            machine = struct.unpack('<H', f.read(2))[0]
            if machine == 0x14c:
                return 'x86', 32
            elif machine == 0x8664:
                return 'x86', 64
            elif machine == 0xAA64:
                return 'ARM64', 64
            elif machine == 0x1C0:
                return 'ARM', 32

    raise ValueError("Unsupported or unknown binary format :(")

def create_capstone_disassembler(arch, bits):   # creates a Capstone disassembler instance based on the architecture and bitness
    if arch == 'x86':
        mode = CS_MODE_64 if bits == 64 else CS_MODE_32
        return Cs(CS_ARCH_X86, mode)
    elif arch == 'ARM':
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == 'ARM64':
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    else:
        raise ValueError("Unsupported architecture :(")




def write_to_file(filepath, string_value, list_value):
    with open(filepath, 'a') as f:
        line = f"{string_value}_{list_value}\n"
        f.write(line)


def bin2csv(bin_path, csv_output_path):     # runs Ghidra headless to convert binary to CSV
    os.makedirs(os.path.dirname(csv_output_path), exist_ok=True)
    print(f"Running Ghidra headless: {bin_path} -> {csv_output_path}")
    result = subprocess.run([
        GHIDRA_PATH,
        PROJECT_DIR,
        "MyProject",
        "-import", bin_path,
        "-scriptPath", os.path.dirname(SCRIPT_PATH),
        "-postScript", os.path.basename(SCRIPT_PATH), csv_output_path,
        "-overwrite"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Ghidra failed for {bin_path}:\n{result.stderr}")
        return False
    return True

def load_ground_truth(csv_path):
    offsets = set()
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            offset = int(row[0], 16)
            offsets.add(offset)
    return offsets

def load_binary(bin_path):
    with open(bin_path, "rb") as f:
        return f.read()

def extract_base_address_from_csv(csv_path):
    with open(csv_path, "r") as f:
        next(f)
        first_line = f.readline().strip()
        offset_str = first_line.split(",")[0]
        return int(offset_str, 16)

def linear_sweep(data, ground_truth, start_offset, base_address): # performs a linear sweep disassembly starting from a random offset
    offset = start_offset
    count = 0
    while offset < len(data):   # iterate until the end of the binary
        try:
            code = data[offset:offset+15]   # read up to 15 bytes (max instruction size)
            virtual_addr = base_address + offset # calculate the virtual address based on the base address and current offset
            instrs = list(md.disasm(code, virtual_addr, count=1)) # disassemble the code using Capstone
            if not instrs:
                return ("invalid", count)   # if no instructions were disassembled, return invalid
            instr = instrs[0]
            if instr.address in ground_truth:
                return ("realign", count)   # if the instruction address is in the ground truth, return realign
            offset += instr.size
            count += 1
        except CsError:
            return ("invalid", count)   # if an error occurs during disassembly, return invalid
    return ("eof", count)


def pick_random_offset(binary_size, ground_truth):
    while True:
        offset = random.randint(0, binary_size - 1)
        if offset not in ground_truth:         # an offset that is not already in the ground truth for obvious reason
            return offset

def process_file(bin_path, csv_path):
    ground_truth = load_ground_truth(csv_path)
    data = load_binary(bin_path)
    base_address = extract_base_address_from_csv(csv_path)
    results = {"realign": [], "invalid": []}
    for _ in range(NUM_TRIALS): # run the linear sweep multiple times
        start_offset = pick_random_offset(len(data), ground_truth)
        outcome, count = linear_sweep(data, ground_truth, start_offset, base_address)   # perform the linear sweep
        if outcome in results:
            results[outcome].append(count)
    write_to_file(JOURNAL_FILE, bin_path, results)  # write the results to the journal file
    return results



def plot_combined(csv_path,results):    # plots the log histogram and the CDF (Cumulative Distribution Function) combined
    base_name = os.path.basename(csv_path.split('.')[0])
    # Create output filename with iteration info
    filename = f"{base_name}_iter_{NUM_TRIALS}_1.png"
    save_path = os.path.join(RESULTS_DIR, filename)

    # Ensure output directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)

    fig, axs = plt.subplots(1, 2, figsize=(16, 6))

    # --- Log Histogram ---
    ax = axs[0]
    for outcome in results:
        if not results[outcome]:
            print(f"No results for outcome: {outcome}")
            continue
        data = results[outcome]
        bins = np.logspace(0, np.log10(max(data)+1), 50)
        ax.hist(data, bins=bins, alpha=0.5, label=outcome, edgecolor='black')
    ax.set_xscale('log')
    ax.set_xlabel("Instructions before stop (log scale)")
    ax.set_ylabel("Frequency")
    ax.set_title("Log Histogram")
    ax.grid(True, which="both", ls="--", linewidth=0.5)
    ax.legend()

    # --- CDF Plot ---
    ax = axs[1]
    for outcome in results:
        if not results[outcome]:
            continue
        data = np.array(results[outcome])
        data_sorted = np.sort(data)
        cdf = np.arange(1, len(data_sorted)+1) / len(data_sorted)
        ax.plot(data_sorted, cdf, label=outcome)
    ax.set_xlabel("Instructions before stop")
    ax.set_ylabel("CDF")
    ax.set_title("CDF Plot")
    ax.grid(True, linestyle="--", linewidth=0.5)
    ax.legend()

    fig.suptitle("Linear Sweep Experiment Results", fontsize=16)
    plt.tight_layout()
    

    plt.savefig(save_path)
    print(f"Plot saved to {save_path}")
    plt.show()
    plt.close()



def plot_combined_stop_data(csv_path, results):   # plots the bar chart and the evolving stop ratio plot combined

    base_name = os.path.basename(csv_path.split('.')[0])

    # Create output filename with iteration info
    filename = f"{base_name}_iter_{NUM_TRIALS}_2.png"
    save_path = os.path.join(RESULTS_DIR, filename)

    # Ensure output directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)


    # Calculate stop percentages for bar plot
    labels = []
    counts = []
    total = sum(len(v) for v in results.values())

    for outcome, data in results.items():
        labels.append(outcome)
        counts.append(len(data) / total * 100)  # percentage

    # Prepare data for evolving stop ratio plot
    all_events = []
    for outcome, counts_list in results.items():
        for instr_count in counts_list:
            all_events.append((instr_count, outcome))
    all_events.sort()

    realign_count = 0
    invalid_count = 0

    instr_counts = []
    realign_ratios = []
    invalid_ratios = []

    for i, (instr, outcome) in enumerate(all_events, 1):
        if outcome == "realign":
            realign_count += 1
        elif outcome == "invalid":
            invalid_count += 1

        total = realign_count + invalid_count
        instr_counts.append(instr)
        realign_ratios.append(realign_count / total)
        invalid_ratios.append(invalid_count / total)

    # Create figure with two subplots side by side
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Bar chart subplot
    bars = ax1.bar(labels, counts, color=["skyblue", "salmon"], edgecolor='black')
    for bar in bars:
        yval = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2.0, yval + 1, f"{yval:.1f}%", ha='center', va='bottom')
    ax1.set_ylabel("Percentage of Stops (%)")
    ax1.set_title("Stop Type Distribution: Realignment vs Invalid")
    ax1.set_ylim(0, 100)
    ax1.grid(axis='y', linestyle="--", linewidth=0.5)

    # Line plot subplot
    ax2.plot(instr_counts, realign_ratios, label="Realign %", color='blue')
    ax2.plot(instr_counts, invalid_ratios, label="Invalid %", color='red')
    ax2.set_xlabel("Instructions before stop")
    ax2.set_ylabel("Cumulative Ratio")
    ax2.set_title("Evolution of Stop Type Over Instructions")
    ax2.grid(True, linestyle="--", linewidth=0.5)
    ax2.legend()
    ax2.set_ylim(0, 1)

    plt.tight_layout()
    


    plt.savefig(save_path)
    print(f"Plot saved to {save_path}")
    plt.show()
    plt.close()



if __name__ == "__main__":
    bin_path = ORIG_BIN_PATH
    archi, bits = detect_architecture(bin_path)
    csv_path = os.path.join(BASE_CSV_DIR, f"{bits}_" + os.path.basename(bin_path) + ".csv")


    # Generate CSV if missing
    if not os.path.exists(csv_path):
        success =bin2csv(bin_path, csv_path)
        if not success:
            print(f"Failed to generate CSV for {bin_path}")
            exit(1)
    else:
        print(f"CSV exists: {csv_path}")

    
    
    md= create_capstone_disassembler(archi, bits)
    md.detail = False

    # Run analysis on this single file
    results = process_file(bin_path, csv_path)

    # Plot
   
    plot_combined(csv_path, results)
    plot_combined_stop_data(csv_path,results)
