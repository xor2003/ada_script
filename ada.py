#!/usr/bin/env python3
"""
main.py: The main orchestrator for the advanced disassembler.
"""

import argparse
import os
import sys
import logging
from database import AnalysisDatabase, ITEM_TYPE_CODE, ITEM_TYPE_DATA
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

    # Configure root logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    configure_logging(log_level)
    
    logger = logging.getLogger("ada")
    logger.info("--- Advanced Non-Interactive Disassembler ---")
    
    # 1. Initialize
    db = AnalysisDatabase()
    logger.debug(f"Database initialized: {db}")

    # 2. Static Loader
    try:
        if not load_mz_exe(args.executable, db):
            logger.error("Failed to load MZ executable")
            sys.exit(1)
        else:
            logger.info("MZ executable loaded successfully")
            logger.debug(f"Post-MZ load: {len(db.segments)} segments, {len(db.memory)} memory bytes, entry at {db.entry_point:05X}")
    except Exception as e:
        logger.error(f"Error loading executable: {str(e)}")
        sys.exit(1)

    # 3. Dynamic Analyzer (The core of auto-analysis)
    analyzer = EmulationAnalyzer(db)
    analyzer.analyze()
    logger.info("Emulation analysis completed")
    logger.debug(f"Post-emulation: {len(db.functions)} functions, {sum(1 for info in db.memory.values() if info.item_type == ITEM_TYPE_CODE)} code bytes, {sum(1 for info in db.memory.values() if info.item_type == ITEM_TYPE_DATA)} data bytes")

    # 4. User Override Script
    if args.script:
        idc_engine = IDCScriptEngine(db)
        try:
            idc_engine.execute_script(args.script)
            logger.info("IDC script executed successfully")
            logger.debug("Post-IDC: Script executed, changes applied to DB")
        except Exception as e:
            logging.error(f"IDC script execution failed: {str(e)}")
            sys.exit(1)
    
    # 5. Output Generation
    LSTGenerator(db).generate(output_lst)
    ASMGenerator(db).generate(output_asm)
    logger.info("Output generation completed")
    logger.debug(f"Post-output: Generated files with {len(db.segments)} segments, {len(db.functions)} functions total")

    # Output completion message to stderr for CLI tests
    print("Disassembly Complete", file=sys.stderr)
    logging.info(f"Output files generated:\n    - {output_asm}\n    - {output_lst}")

if __name__ == "__main__":
    main()
