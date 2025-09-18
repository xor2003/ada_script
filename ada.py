#!/usr/bin/env python3
"""
Ada Script: IDC Engine and MZ Parser
Entry point for command-line usage.
"""

import argparse
import sys
from idc_engine import parse_idc  # Import main parser
from mz_parser import parse_mz_file  # Import MZ parser

def main():
    parser = argparse.ArgumentParser(
        description="Ada Script: Parse MZ files and apply IDC scripts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.mz -s script.idc --debug    Parse MZ and apply IDC
  %(prog)s input.mz --debug                 Parse MZ only
        """
    )
    parser.add_argument("mz_file", help="Path to MZ file (e.g., egame.exe)")
    parser.add_argument("-s", "--script", help="Path to IDC script (e.g., egame.idc)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--version", action="version", version="Ada Script 0.1.0")

    args = parser.parse_args()

    if args.debug:
        print(f"Debug mode: Parsing MZ file '{args.mz_file}'", file=sys.stderr)

    # Parse MZ file
    try:
        mz_data = parse_mz_file(args.mz_file)
        if args.debug:
            print(f"MZ parsed successfully: {len(mz_data)} sections", file=sys.stderr)
    except Exception as e:
        print(f"Error parsing MZ: {e}", file=sys.stderr)
        sys.exit(1)

    # Apply IDC script if provided
    if args.script:
        if args.debug:
            print(f"Applying IDC script '{args.script}'", file=sys.stderr)
        try:
            idc_result = parse_idc(args.script, mz_data, strict=True)
            if idc_result is None or len(idc_result.functions) == 0:  # Check if partial/empty
                print("Error applying IDC: Parsing failed", file=sys.stderr)
                sys.exit(1)
            if args.debug:
                print(f"IDC applied: {idc_result}", file=sys.stderr)
            # Output result (stub: print summary)
            print(f"Processed: {idc_result}")
        except Exception as e:
            print(f"Error applying IDC: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Just output MZ info (stub)
        print(f"MZ file parsed: {args.mz_file}")
    print(f"Done.")

if __name__ == "__main__":
    main()
