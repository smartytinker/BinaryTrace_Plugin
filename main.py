"""
main.py
CLI entry point for the Malware Analysis tool.
"""
import argparse
import json
import logging
import sys
from analyzer import MalwareAnalyzer
from errors import AnalyzerBaseError


def setup_logging(debug: bool = False):
    """Configures console logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def main():
    parser = argparse.ArgumentParser(description="Binary Ninja Malware Extractor & Analyzer")
    parser.add_argument("target", help="Path to the binary file to analyze (.exe, .dll, etc.)")
    parser.add_argument("-o", "--output", help="Path to save the JSON report", type=str)
    parser.add_argument("--debug", help="Enable debug logging", action="store_true")
    
    args = parser.parse_args()
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)

    try:
        # Use a context manager to ensure the BinaryView is properly closed
        with MalwareAnalyzer(args.target) as analyzer:
            report = analyzer.run_full_analysis()

            # Output results
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(report.to_dict(), f, indent=4) # NEW: added .to_dict()
                logger.info(f"Report saved to {args.output}")
            else:
                print("\n--- ANALYSIS REPORT ---")
                print(json.dumps(report.to_dict(), indent=4)) # NEW: added .to_dict()

    except AnalyzerBaseError as e:
        logger.error(f"Analysis aborted: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected critical error occurred: {e}", exc_info=args.debug)
        sys.exit(1)

if __name__ == "__main__":
    main()