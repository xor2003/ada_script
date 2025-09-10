#!/usr/bin/env python3
"""
main.py: The main orchestrator for the advanced disassembler.
"""

import argparse
import os
import sys
import logging
from database import AnalysisDatabase
from mz_parser import load_mz_exe
from emulation_analyzer import EmulationAnalyzer
from idc_engine import IDCScriptEngine
from output_generator import LSTGenerator, ASMGenerator

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

def main():
    parser = argparse.ArgumentParser(
        description="An emulation-driven, non-interactive disassembler for DOS MZ-EXE files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("executable", help="Path to the DOS MZ-EXE file to disassemble.")
    parser.add_argument("-s", "--script", help="Path to an IDA-compatible .idc script to apply.")
    parser.add_argument("-o", "--output", help="Base name for the output files (e.g., 'my_program').")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if not os.path.exists(args.executable):
        print(f"[!] Error: Executable file not found: '{args.executable}'", file=sys.stderr)
        sys.exit(1)
    
    if args.script and not os.path.exists(args.script):
        print(f"[!] Error: IDC script not found: '{args.script}'", file=sys.stderr)
        sys.exit(1)

    output_base = args.output or os.path.splitext(os.path.basename(args.executable))[0]
    output_asm, output_lst = f"{output_base}.asm", f"{output_base}.lst"

    logging.info("--- Advanced Non-Interactive Disassembler ---")
    
    # 1. Initialize
    db = AnalysisDatabase()

    # 2. Static Loader
    if not load_mz_exe(args.executable, db):
        sys.exit(1)

    # 3. Dynamic Analyzer (The core of auto-analysis)
    analyzer = EmulationAnalyzer(db)
    analyzer.analyze()

    # 4. User Override Script
    if args.script:
        idc_engine = IDCScriptEngine(db)
        idc_engine.execute_script(args.script)
    
    # 5. Output Generation
    LSTGenerator(db).generate(output_lst)
    ASMGenerator(db).generate(output_asm)

    logging.info("--- Disassembly Complete ---")
    logging.info(f"Output files generated:\n    - {output_asm}\n    - {output_lst}")

if __name__ == "__main__":
    main()
