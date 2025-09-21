#!/usr/bin/env python3
"""
Ada Script: Full Binary Analysis Pipeline
Integrates MZ parsing, IDC application, emulation analysis, and output generation (.lst/.asm).
Flags drive optional steps: --full (functions/CFG), --classify (entropy-based), --xrefs (cross-refs).
"""

import argparse
import logging
import sys
from pathlib import Path

# Module imports for pipeline
from mz_parser import MZParser
from emulation_analyzer import EmulationAnalyzer
from output_generator import OutputGenerator
from database import Database
import sqlite3  # For queries in report

from idc_engine import parse_idc

def generate_asm_simple(db: Database, output_file: str, binary: bytes):
    """Simple .asm generator: Query instructions → ASM format."""
    try:
        conn = db.conn
        insts = conn.execute("SELECT addr, mnem, op_str FROM instructions WHERE type='code' ORDER BY addr").fetchall()
        with open(output_file, 'w') as f:
            f.write(f"; Simple ASM for {output_file}\n")
            for addr, mnem, op_str in insts[:1000]:  # Limit for perf
                if op_str:
                    f.write(f"{hex(addr)}: {mnem} {op_str}\n")
                else:
                    f.write(f"{hex(addr)}: {mnem}\n")
        logging.info(f"ASM generated: {output_file} ({len(insts)} insts)")
    except Exception as e:
        logging.warning(f"ASM gen failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Full Binary Analysis Pipeline.")
    parser.add_argument("binary", nargs='?', help="Path to binary file (e.g., .exe)")
    parser.add_argument("-s", "--idc-script", help="IDC script to apply")
    parser.add_argument("-o", "--output", default="analysis.md", help="MD report (default: analysis.md)")
    parser.add_argument("--debug", action="store_true", help="Debug logging")
    parser.add_argument("--full", action="store_true", help="Full analysis (functions, CFG)")
    parser.add_argument("--classify", action="store_true", help="Classify code/data")
    parser.add_argument("--xrefs", action="store_true", help="Compute cross-references")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1.0')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.binary is None:
        parser.print_help()
        sys.exit(1)

    binary_path = Path(args.binary)
    if not binary_path.exists():
        logging.error(f"Binary not found: {binary_path}")
        sys.exit(1)

    logging.info(f"Starting analysis of {binary_path.name} (debug: {args.debug})")

    try:
        # Load binary
        with open(binary_path, 'rb') as f:
            binary = f.read()
        logging.info(f"Loaded binary: {binary_path.name} ({len(binary)} bytes)")

        # Step 1: MZ Parsing
        mz_parser = MZParser(binary)
        db = mz_parser.parse()
        logging.info("MZ parsing complete")

        # Step 2: Apply IDC (if provided) and insert to DB
        if args.idc_script:
            idc_path = Path(args.idc_script)
            if idc_path.exists():
                with open(idc_path, 'r') as f:
                    idc_content = f.read()
                script = parse_idc(idc_content, db, strict=args.debug)  # Strict if debug for better errors
                if script is None or (len(script.functions) == 0 and len(script.variables) == 0 and len(script.includes) == 0 and len(script.defines) == 0):
                    logging.error(f"IDC parse failed for {idc_path}: empty or None script")
                    sys.exit(1)
                logging.info(f"IDC applied: {script}")
                script.insert_to_db()
            else:
                logging.warning(f"IDC not found: {idc_path}")

        # Step 3: Emulation Analysis (disasm, classify, functions, xrefs)
        analyzer = EmulationAnalyzer(binary, db, full=args.full, classify=args.classify, xrefs=args.xrefs)
        analyzer.analyze()
        db.binary = binary  # For generator

        # Step 4: Generate Outputs
        generator = OutputGenerator(db)
        stem = binary_path.stem
        lst_file = f"{stem}.lst"
        generator.generate_lst(lst_file)

        # Generate .asm (simple fallback)
        asm_file = f"{stem}.asm"
        generate_asm_simple(db, asm_file, binary)

        # Step 5: MD Report (query DB)
        conn = db.conn
        num_insts = conn.execute("SELECT COUNT(*) FROM instructions").fetchone()[0]
        num_funcs = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
        coverage = conn.execute("SELECT value FROM stats WHERE key='code_coverage'").fetchone()
        coverage = coverage[0] if coverage else 0
        funcs = conn.execute("SELECT start, name FROM functions LIMIT 10").fetchall()
        comments = conn.execute("SELECT addr, comment FROM comments LIMIT 5").fetchall()

        with open(args.output, "w") as f:
            f.write("# Binary Analysis Report\n")
            f.write(f"## File: {binary_path.name} ({len(binary)} bytes)\n")
            f.write("### Summary\n")
            f.write(f"- Instructions: {num_insts}\n")
            f.write(f"- Functions: {num_funcs}\n")
            f.write(f"- Coverage: {coverage:.1f}%\n")
            f.write("### Functions (Top 10)\n")
            for start, name in funcs:
                f.write(f"- {hex(start)}: {name}\n")
            f.write("### Comments (Top 5)\n")
            for addr, text in comments:
                f.write(f"- {hex(addr)}: {text}\n")
            f.write(f"### Outputs\n- LST: {lst_file}\n- ASM: {asm_file}\n")

        logging.info(f"Pipeline complete. MD: {args.output}, LST: {lst_file}, ASM: {asm_file}")

    except Exception as e:
        logging.exception("Pipeline failed")
        sys.exit(1)
    finally:
        if 'db' in locals():
            db.close()

if __name__ == "__main__":
    main()
