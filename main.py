"""
main.py
CLI entry point for the Enterprise Malware Analysis tool.
Supports single-file analysis and bulk-directory processing.
"""
import argparse
import json
import logging
import sys
import os
import glob
from analyzer import MalwareAnalyzer
from threat_intel import ThreatIntelEngine
from database import DatabaseManager

def setup_logging(debug: bool = False):
    """Configures console logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def process_file(filepath: str, db: DatabaseManager, output_dir: str = None) -> dict:
    """Processes a single file, utilizing the database cache if available."""
    logger = logging.getLogger(__name__)
    ti_engine = ThreatIntelEngine(filepath)
    file_hash = ti_engine.get_file_hash()

    # 1. Check Cache
    if db.sample_exists(file_hash):
        logger.info(f"[CACHE HIT] Skipping analysis, loading from DB: {filepath}")
        cached_report = db.get_report(file_hash)
        report_dict = cached_report.to_dict() if cached_report else {"error": "Cache load failed"}
    
    # 2. Run Full Analysis
    else:
        logger.info(f"[NEW SAMPLE] Running full triage: {filepath}")
        try:
            with MalwareAnalyzer(filepath) as analyzer:
                strings = analyzer.extract_strings()
                urls, ips = analyzer.filter_iocs(strings)
                threat_intel = ti_engine.gather_intelligence(ips)

                report = analyzer.run_full_analysis()
                report.threat_intel = threat_intel

                # Save to DB
                db.save_report(report)
                report_dict = report.to_dict()
        except Exception as e:
            logger.error(f"Failed to analyze {filepath}: {e}")
            return {"file": filepath, "error": str(e)}

    # 3. Handle Output Output
    if output_dir:
        out_path = os.path.join(output_dir, f"{file_hash}.json")
        with open(out_path, "w") as f:
            json.dump(report_dict, f, indent=4)
        logger.info(f"Report saved -> {out_path}")

    return report_dict

def main():
    parser = argparse.ArgumentParser(description="BinaryTrace Enterprise Engine")
    parser.add_argument("target", help="Path to a binary file OR a directory of binaries")
    parser.add_argument("-o", "--outdir", help="Directory to save JSON reports", type=str)
    parser.add_argument("--debug", help="Enable debug logging", action="store_true")
    
    args = parser.parse_args()
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)
    db = DatabaseManager()

    if args.outdir and not os.path.exists(args.outdir):
        os.makedirs(args.outdir)

    try:
        if os.path.isfile(args.target):
            # Single File Mode
            report = process_file(args.target, db, args.outdir)
            if not args.outdir:
                print("\n--- ANALYSIS REPORT ---")
                print(json.dumps(report, indent=4))

        elif os.path.isdir(args.target):
            # Batch Directory Mode
            logger.info(f"Starting batch analysis on directory: {args.target}")
            
            # Find all common executables
            extensions = ('*.exe', '*.dll', '*.bin', '*.elf')
            files_to_scan = []
            for ext in extensions:
                files_to_scan.extend(glob.glob(os.path.join(args.target, ext)))
            
            logger.info(f"Found {len(files_to_scan)} files to analyze.")
            
            success_count = 0
            for file_path in files_to_scan:
                result = process_file(file_path, db, args.outdir)
                if "error" not in result:
                    success_count += 1
                    
            logger.info(f"Batch complete. Successfully processed {success_count}/{len(files_to_scan)} files.")
            
        else:
            logger.error(f"Target not found: {args.target}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Pipeline crashed: {e}", exc_info=args.debug)
        sys.exit(1)

if __name__ == "__main__":
    main()