#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP Request Smuggling Detector - Automated Execution Engine
Author: SYLHETYHACKVENGER (THE-ERROR808)
Version: 3.0
Description: Automated runner for comprehensive HRS detection with enhanced features
"""

import os
import sys
import json
import time
import logging
import subprocess
import argparse
import signal
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
try:
    from termcolor import colored, cprint
    from pyfiglet import figlet_format
except ImportError:
    print("[!] Required packages not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor", "pyfiglet"])
    from termcolor import colored, cprint
    from pyfiglet import figlet_format

# ============================================================
# CONSTANTS & CONFIGURATION
# ============================================================

class Config:
    """Configuration management for the runner."""
    
    # File paths
    DETECTOR_SCRIPT = "hrs_detector.py"
    REPORT_DIR = "reports"
    LOG_FILE = os.path.join(REPORT_DIR, "runner.log")
    RESULTS_FILE = os.path.join(REPORT_DIR, "execution_log.json")
    
    # Default scan parameters
    DEFAULT_TIMEOUT = 15
    DEFAULT_RETRY = 3
    DEFAULT_DELAY = 2
    DEFAULT_WORKERS = 5
    DEFAULT_MAX_WORKERS = 10
    
    # Color scheme
    COLORS = {
        'success': 'green',
        'error': 'red',
        'warning': 'yellow',
        'info': 'cyan',
        'highlight': 'magenta',
        'title': 'blue'
    }
    
    # Banner ASCII art
    BANNER = r"""
........
:      :
: :'': :
: :..: :...
:    : :
''''': :'''
     : :
...  : :
: :  : :
: :  : :
: :  : :
: :  : :
: :  : :  .
: :  : :  :'.
: :..: :..:.:..
:    : :       '.
''''': :'':':'''''
.....:.:..:.:........
:                    '.
: :'':':'':':'''''''''''
: :..: :  : :...............
:      :  :                :
''''''''  ''''''''''''''''''
The CLTEcho 
HTTP Request Smuggling Detector - Automated Execution Engine

"""
    
    AUTHOR = "SYLHETYHACKVENGER (THE-ERROR808)"
    TITLE = "THIS TOOLS IS ONLY FOR EDUCATIONAL PURPOSES AND RESEARCHES NEVER MISUSE IT."
    VERSION = "3.0"

# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ScanResult:
    """Data class for storing scan results."""
    target: str
    timestamp: str
    duration_seconds: float
    vulnerable: bool
    exit_code: int
    output_summary: str
    error: Optional[str] = None
    findings_count: int = 0
    threats_detected: List[str] = None
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

@dataclass
class ScanSummary:
    """Data class for scan summary statistics."""
    total_targets: int
    vulnerable_targets: int
    safe_targets: int
    error_targets: int
    total_duration: float
    average_duration: float
    start_time: str
    end_time: str
    findings_summary: Dict[str, int]

# ============================================================
# LOGGING SETUP
# ============================================================

class Logger:
    """Custom logger with colored output."""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging system."""
        # Create logs directory
        if self.log_file:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Configure root logger
        self.logger = logging.getLogger('HRSRunner')
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler with colored output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(self._ColoredFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(file_handler)
    
    class _ColoredFormatter(logging.Formatter):
        """Custom formatter with colors."""
        
        COLORS = {
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red'
        }
        
        def format(self, record):
            levelname = record.levelname
            color = self.COLORS.get(levelname, 'white')
            record.levelname = colored(levelname, color, attrs=['bold'])
            record.msg = colored(record.msg, 'white')
            return super().format(record)
    
    def debug(self, msg):
        self.logger.debug(msg)
    
    def info(self, msg):
        self.logger.info(msg)
    
    def warning(self, msg):
        self.logger.warning(msg)
    
    def error(self, msg):
        self.logger.error(msg)
    
    def critical(self, msg):
        self.logger.critical(msg)

# ============================================================
# UI COMPONENTS
# ============================================================

class UI:
    """User interface components."""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def print_banner(self):
        """Display the banner with styling."""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # Banner
        print(colored(Config.BANNER, Config.COLORS['info']))
        
        # Separator
        print(colored("=" * 80, Config.COLORS['warning']))
        
        # Author and title
        print(colored(f"Author : {Config.AUTHOR}", Config.COLORS['success'], attrs=['bold']))
        print(colored(f"Title  : {Config.TITLE}", Config.COLORS['error'], attrs=['bold']))
        print(colored(f"Version: {Config.VERSION}", Config.COLORS['highlight']))
        
        # Separator
        print(colored("=" * 80, Config.COLORS['warning']))
        print()
    
    def print_section(self, title: str, char: str = "=", length: int = 80):
        """Print a section header."""
        print(colored(char * length, Config.COLORS['info']))
        print(colored(f" {title} ".center(length, char), Config.COLORS['highlight'], attrs=['bold']))
        print(colored(char * length, Config.COLORS['info']))
        print()
    
    def print_table(self, headers: List[str], rows: List[List[str]]):
        """Print a formatted table."""
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_str = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
        print(colored(header_str, Config.COLORS['highlight'], attrs=['bold']))
        print(colored("-" * len(header_str), Config.COLORS['warning']))
        
        # Print rows
        for row in rows:
            row_str = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
            print(row_str)
        print()
    
    def print_progress(self, current: int, total: int, status: str = ""):
        """Print a progress bar."""
        progress = current / total
        bar_length = 50
        filled = int(bar_length * progress)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        percentage = progress * 100
        status_text = f" {status}" if status else ""
        
        sys.stdout.write(f"\r[{bar}] {current}/{total} ({percentage:.1f}%){status_text}")
        sys.stdout.flush()
    
    def get_confirmation(self, prompt: str = "Continue?") -> bool:
        """Get user confirmation."""
        while True:
            response = input(colored(f"[?] {prompt} (y/n): ", Config.COLORS['warning'])).strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                print(colored("[!] Please enter 'y' or 'n'", Config.COLORS['error']))

# ============================================================
# CORE ENGINE
# ============================================================

class HRSRunner:
    """Main execution engine for HRS detection."""
    
    def __init__(self):
        self.logger = Logger(Config.LOG_FILE)
        self.ui = UI(self.logger)
        self.results: List[ScanResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.interrupted = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully."""
        self.interrupted = True
        print(colored("\n\n[!] Interrupt signal received. Cleaning up...", Config.COLORS['warning']))
    
    def validate_environment(self) -> bool:
        """Validate the execution environment."""
        self.logger.info("Validating environment...")
        
        # Check Python version
        if sys.version_info < (3, 6):
            self.logger.error(f"Python 3.6+ required, found {sys.version}")
            return False
        
        # Check detector script
        if not os.path.isfile(Config.DETECTOR_SCRIPT):
            self.logger.error(f"Detector script not found: {Config.DETECTOR_SCRIPT}")
            return False
        
        self.logger.info(f"Detector script found: {Config.DETECTOR_SCRIPT}")
        
        # Check dependencies
        try:
            import termcolor, pyfiglet
        except ImportError:
            self.logger.warning("Some dependencies missing. Attempting to install...")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install",
                    "termcolor", "pyfiglet", "--quiet"
                ])
                self.logger.info("Dependencies installed successfully")
            except Exception as e:
                self.logger.error(f"Failed to install dependencies: {e}")
                return False
        
        # Create report directory
        os.makedirs(Config.REPORT_DIR, exist_ok=True)
        self.logger.info(f"Report directory: {Config.REPORT_DIR}")
        
        return True
    
    def load_targets(self, url: Optional[str] = None, file_path: Optional[str] = None) -> List[str]:
        """Load targets from URL or file."""
        targets = []
        
        if url:
            targets.append(url)
            self.logger.info(f"Added target from URL: {url}")
        
        if file_path:
            if not os.path.isfile(file_path):
                self.logger.error(f"Target file not found: {file_path}")
                return targets
            
            with open(file_path, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
            self.logger.info(f"Loaded {len(file_targets)} targets from file: {file_path}")
        
        return list(set(targets))  # Remove duplicates
    
    def run_single_scan(self, target: str, timeout: int, retry: int, workers: int) -> ScanResult:
        """Run a single scan on a target."""
        start_time = datetime.now()
        
        # Build command
        cmd = [
            sys.executable,
            Config.DETECTOR_SCRIPT,
            "-u", target,
            "--enhanced",
            "--concurrent",
            "-t", str(timeout),
            "-r", str(retry),
            "--max-workers", str(min(workers, Config.DEFAULT_MAX_WORKERS)),
            "-o", Config.REPORT_DIR
        ]
        
        self.logger.info(f"Starting scan for: {target}")
        
        try:
            # Run the detector
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * 3  # Extended timeout
            )
            
            output = process.stdout + process.stderr
            
            # Parse results
            is_vulnerable = "VULNERABILITY DETECTED" in output or "VULNERABLE" in output
            
            # Extract findings count
            findings_count = 0
            if "Findings:" in output:
                try:
                    findings_line = [l for l in output.split('\n') if "Findings:" in l][0]
                    findings_count = int(''.join(filter(str.isdigit, findings_line)) or 0)
                except:
                    pass
            
            # Extract threats detected
            threats = []
            threat_patterns = ["CL.TE", "TE.CL", "TE.TE", "CL.CL", "CL.0", "TE.0"]
            for threat in threat_patterns:
                if threat in output:
                    threats.append(threat)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = ScanResult(
                target=target,
                timestamp=start_time.isoformat(),
                duration_seconds=duration,
                vulnerable=is_vulnerable,
                exit_code=process.returncode,
                output_summary=output[-1000:] if len(output) > 1000 else output,
                findings_count=findings_count,
                threats_detected=threats
            )
            
            self.logger.info(f"Completed scan for {target} in {duration:.2f}s")
            if is_vulnerable:
                self.logger.warning(f"VULNERABILITY DETECTED in {target}")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timeout for {target}")
            return ScanResult(
                target=target,
                timestamp=start_time.isoformat(),
                duration_seconds=timeout * 3,
                vulnerable=False,
                exit_code=-1,
                output_summary="Timeout",
                error="Scan timed out"
            )
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {e}")
            return ScanResult(
                target=target,
                timestamp=start_time.isoformat(),
                duration_seconds=0,
                vulnerable=False,
                exit_code=-1,
                output_summary=str(e),
                error=str(e)
            )
    
    def run_sequential(self, targets: List[str], timeout: int, retry: int, delay: int, workers: int):
        """Run scans sequentially."""
        total = len(targets)
        
        for i, target in enumerate(targets, 1):
            if self.interrupted:
                break
            
            self.ui.print_progress(i - 1, total, f"Preparing scan {i}/{total}")
            
            # Display target info
            self.logger.info(f"\n[{i}/{total}] Scanning: {target}")
            
            # Run scan
            result = self.run_single_scan(target, timeout, retry, workers)
            self.results.append(result)
            
            # Update progress
            status = "VULNERABLE" if result.vulnerable else "SAFE"
            if result.error:
                status = "ERROR"
            self.ui.print_progress(i, total, f"{status} - {target[:50]}")
            
            # Wait before next scan
            if i < total and not self.interrupted:
                time.sleep(delay)
        
        print()  # Newline after progress bar
    
    def run_parallel(self, targets: List[str], timeout: int, retry: int, workers: int):
        """Run scans in parallel."""
        total = len(targets)
        self.logger.info(f"Starting parallel scan with {workers} workers")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all tasks
            future_to_target = {
                executor.submit(self.run_single_scan, target, timeout, retry, workers): target
                for target in targets
            }
            
            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_target):
                if self.interrupted:
                    break
                
                target = future_to_target[future]
                completed += 1
                
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    status = "VULNERABLE" if result.vulnerable else "SAFE"
                    if result.error:
                        status = "ERROR"
                    
                    self.ui.print_progress(
                        completed, 
                        total, 
                        f"{status} - {target[:50]}"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error processing {target}: {e}")
                    self.results.append(ScanResult(
                        target=target,
                        timestamp=datetime.now().isoformat(),
                        duration_seconds=0,
                        vulnerable=False,
                        exit_code=-1,
                        output_summary="",
                        error=str(e)
                    ))
        
        print()  # Newline after progress bar
    
    def generate_summary(self) -> ScanSummary:
        """Generate summary statistics from results."""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.vulnerable)
        errors = sum(1 for r in self.results if r.error)
        safe = total - vulnerable - errors
        
        total_duration = sum(r.duration_seconds for r in self.results)
        avg_duration = total_duration / total if total > 0 else 0
        
        # Findings summary
        findings_summary = {}
        for result in self.results:
            for threat in result.threats_detected:
                findings_summary[threat] = findings_summary.get(threat, 0) + 1
        
        return ScanSummary(
            total_targets=total,
            vulnerable_targets=vulnerable,
            safe_targets=safe,
            error_targets=errors,
            total_duration=total_duration,
            average_duration=avg_duration,
            start_time=self.start_time.isoformat() if self.start_time else "",
            end_time=self.end_time.isoformat() if self.end_time else "",
            findings_summary=findings_summary
        )
    
    def save_results(self):
        """Save results to JSON file."""
        try:
            # Convert results to dict
            results_dict = [r.to_dict() for r in self.results]
            
            # Add summary
            summary = self.generate_summary()
            data = {
                "summary": asdict(summary),
                "results": results_dict
            }
            
            # Save to file
            with open(Config.RESULTS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Results saved to: {Config.RESULTS_FILE}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
    
    def display_summary(self):
        """Display scan summary."""
        summary = self.generate_summary()
        
        self.ui.print_section("SCAN SUMMARY")
        
        # Table data
        headers = ["Metric", "Value"]
        rows = [
            ["Total Targets", str(summary.total_targets)],
            ["Vulnerable", colored(str(summary.vulnerable_targets), Config.COLORS['error'])],
            ["Safe", colored(str(summary.safe_targets), Config.COLORS['success'])],
            ["Errors", colored(str(summary.error_targets), Config.COLORS['warning'])],
            ["Total Duration", f"{summary.total_duration:.2f}s"],
            ["Average Duration", f"{summary.average_duration:.2f}s"],
        ]
        self.ui.print_table(headers, rows)
        
        # Findings summary
        if summary.findings_summary:
            print(colored("Threats Detected:", Config.COLORS['highlight'], attrs=['bold']))
            for threat, count in summary.findings_summary.items():
                print(f"  - {threat}: {count} target(s)")
            print()
        
        # List vulnerable targets
        if summary.vulnerable_targets > 0:
            print(colored("Vulnerable Targets:", Config.COLORS['error'], attrs=['bold']))
            for result in self.results:
                if result.vulnerable:
                    print(f"  - {result.target}")
            print()
        
        # List errors
        if summary.error_targets > 0:
            print(colored("Targets with Errors:", Config.COLORS['warning'], attrs=['bold']))
            for result in self.results:
                if result.error:
                    print(f"  - {result.target}: {result.error}")
            print()
    
    def run(self):
        """Main execution method."""
        try:
            # Display banner
            self.ui.print_banner()
            
            # Parse arguments
            parser = argparse.ArgumentParser(
                description="Automated HTTP Request Smuggling Detector Runner",
                formatter_class=argparse.RawDescriptionHelpFormatter
            )
            
            parser.add_argument(
                "-u", "--url",
                help="Single target URL"
            )
            parser.add_argument(
                "-f", "--file",
                help="File containing list of URLs (one per line)"
            )
            parser.add_argument(
                "-t", "--timeout",
                type=int,
                default=Config.DEFAULT_TIMEOUT,
                help=f"Socket timeout in seconds (default: {Config.DEFAULT_TIMEOUT})"
            )
            parser.add_argument(
                "-r", "--retry",
                type=int,
                default=Config.DEFAULT_RETRY,
                help=f"Retry count for each payload (default: {Config.DEFAULT_RETRY})"
            )
            parser.add_argument(
                "-d", "--delay",
                type=int,
                default=Config.DEFAULT_DELAY,
                help=f"Delay between scans in seconds (default: {Config.DEFAULT_DELAY})"
            )
            parser.add_argument(
                "-w", "--workers",
                type=int,
                default=Config.DEFAULT_WORKERS,
                help=f"Number of parallel workers (default: {Config.DEFAULT_WORKERS})"
            )
            parser.add_argument(
                "-p", "--parallel",
                action="store_true",
                help="Enable parallel scanning"
            )
            parser.add_argument(
                "--no-confirm",
                action="store_true",
                help="Skip confirmation prompt"
            )
            
            args = parser.parse_args()
            
            # Validate inputs
            if not args.url and not args.file:
                self.logger.error("Please provide a target URL (-u) or file (-f)")
                parser.print_help()
                sys.exit(1)
            
            # Validate environment
            if not self.validate_environment():
                sys.exit(1)
            
            # Load targets
            targets = self.load_targets(args.url, args.file)
            if not targets:
                self.logger.error("No targets loaded")
                sys.exit(1)
            
            self.logger.info(f"Loaded {len(targets)} target(s)")
            
            # Display target list
            self.ui.print_section("TARGET LIST", char="-")
            for i, target in enumerate(targets, 1):
                print(f"  {i}. {target}")
            print()
            
            # Confirmation
            if not args.no_confirm:
                if not self.ui.get_confirmation("Ready to start scanning"):
                    self.logger.info("Aborted by user")
                    sys.exit(0)
            
            # Start scan
            self.start_time = datetime.now()
            self.ui.print_section("SCANNING IN PROGRESS")
            
            if args.parallel and len(targets) > 1:
                self.logger.info(f"Using parallel mode with {args.workers} workers")
                self.run_parallel(targets, args.timeout, args.retry, args.workers)
            else:
                self.logger.info("Using sequential mode")
                self.run_sequential(targets, args.timeout, args.retry, args.delay, args.workers)
            
            self.end_time = datetime.now()
            
            # Save and display results
            self.save_results()
            self.display_summary()
            
            # Completion message
            if self.interrupted:
                self.logger.warning("Scan was interrupted")
            else:
                self.logger.info("Scan completed successfully")
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

# ============================================================
# ENTRY POINT
# ============================================================

def main():
    """Main entry point."""
    runner = HRSRunner()
    runner.run()

if __name__ == "__main__":
    main()
