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

# Configure logging with adjustable level
def configure_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

# Set default log level
log_level = logging.INFO

def main():
    parser = argparse.ArgumentParser(
        description="An emulation-driven, non-interactive disassembler for DOS MZ-EXE files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("executable", help="Path to the DOS MZ-EXE file to disassemble.")
    parser.add_argument("-s", "--script", help="Path to an IDA-compatible .idc script to apply.")
    parser.add_argument("-o", "--output", help="Base name for the output files (e.g., 'my_program').")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
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

    # Configure logging with adjustable level
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logger = logging.getLogger("ada")
    logger.setLevel(log_level)
    
    # Create a handler and formatter
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Add the handler to the logger if it doesn't have one already
    if not logger.handlers:
        logger.addHandler(handler)
    
    logger.propagate = False
    logger.info("--- Advanced Non-Interactive Disassembler ---")
    
    # 1. Initialize
    db = AnalysisDatabase()
    logger.debug(f"Database initialized: {db}")

    # 2. Static Loader
    try:
        if not load_mz_exe(args.executable, db):
            logger.error("Failed to load MZ executable")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading executable: {str(e)}")
        sys.exit(1)

    # 3. Dynamic Analyzer (The core of auto-analysis)
    analyzer = EmulationAnalyzer(db)
    analyzer.analyze()

    # 4. User Override Script
    if args.script:
        idc_engine = IDCScriptEngine(db)
        try:
            idc_engine.execute_script(args.script)
        except Exception as e:
            logging.error(f"IDC script execution failed: {str(e)}")
            sys.exit(1)
    
    # 5. Output Generation
    LSTGenerator(db).generate(output_lst)
    ASMGenerator(db).generate(output_asm)

    # Output completion message to stderr for CLI tests
    print("Disassembly Complete", file=sys.stderr)
    logging.info(f"Output files generated:\n    - {output_asm}\n    - {output_lst}")

if __name__ == "__main__":
    main()
