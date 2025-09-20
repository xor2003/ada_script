#!/usr/bin/env python3
"""
Ada Script: IDC Engine and MZ Parser
Entry point for command-line usage.
"""
import argparse
import sys
import traceback
import logging

# Setup logging early
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from idc_engine import parse_idc  # Import main parser
    logger.info("IDC engine imported successfully")
except ImportError as e:
    logger.error(f"Failed to import idc_engine: {e}")
    sys.exit(1)

try:
    from mz_parser import parse_mz_file  # Import MZ parser
    logger.info("MZ parser imported successfully")
except ImportError as e:
    logger.error(f"Failed to import mz_parser: {e}")
    sys.exit(1)

try:
    from emulation_analyzer import emulate  # Import emulation module
    logger.info("Emulation analyzer imported successfully")
except ImportError as e:
    logger.error(f"Failed to import emulation_analyzer: {e}")
    sys.exit(1)

try:
    from output_generator import generate_outputs  # Import output generator
    logger.info("Output generator imported successfully")
except ImportError as e:
    logger.error(f"Failed to import output_generator: {e}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Ada Script: Parse MZ files and apply IDC scripts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.mz -s script.idc --debug    Parse MZ, apply IDC, emulate, and generate outputs
  %(prog)s input.mz --debug                 Parse MZ only
        """
    )
    parser.add_argument("mz_file", help="Path to MZ file (e.g., egame.exe)")
    parser.add_argument("-s", "--script", help="Path to IDC script (e.g., egame.idc)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--version", action="version", version="Ada Script 0.1.0")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        print(f"Debug mode: Parsing MZ file '{args.mz_file}'", file=sys.stderr)
        logger.debug(f"Debug mode enabled")

    # Parse MZ file
    try:
        logger.info(f"Parsing MZ file: {args.mz_file}")
        mz_data = parse_mz_file(args.mz_file)
        logger.info("MZ parsed successfully")
        if args.debug:
            print(f"MZ parsed successfully: {len(mz_data.get('segments', []))} segments", file=sys.stderr)
    except Exception as e:
        logger.error(f"Error parsing MZ: {e}")
        print(f"Error parsing MZ: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    # Apply IDC script if provided
    if args.script:
        if args.debug:
            print(f"Applying IDC script '{args.script}'", file=sys.stderr)
        try:
            logger.info(f"Applying IDC script: {args.script}")
            idc_result = parse_idc(args.script, mz_data, strict=True)
            if idc_result is None or len(idc_result.functions) == 0:  # Check if parsing failed or empty
                logger.warning("IDC parsing returned None or empty functions")
                print("Error applying IDC: Parsing failed", file=sys.stderr)
                sys.exit(1)
            logger.info(f"IDC applied successfully: {idc_result}")
            if args.debug:
                print(f"IDC applied: {idc_result}", file=sys.stderr)
            # Execute emulation
            print("Executing emulation...")
            logger.info("Starting emulation")
            emulated_db = emulate(idc_result, mz_data)
            print("Emulation completed successfully.")
            logger.info("Emulation completed")
            # Generate outputs (unconditional for full pipeline)
            print("Generating output files...")
            logger.info("Generating outputs")
            generate_outputs(emulated_db, args.mz_file)
            print("Output files generated: .lst and .asm")
            logger.info("Outputs generated")
        except Exception as e:
            logger.error(f"Error in emulation or output generation: {e}")
            print(f"Error in emulation or output generation: {e}", file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)
    else:
        # Just output MZ info (stub)
        print(f"MZ file parsed: {args.mz_file}")
        logger.info("No IDC script; MZ only")
        if args.debug:
            print("No IDC script provided; skipping application, emulation, and output generation.", file=sys.stderr)

    print("Done.")

if __name__ == "__main__":
    main()
