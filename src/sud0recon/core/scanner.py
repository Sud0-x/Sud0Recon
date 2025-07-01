"""
Core scanner module for Sud0Recon

This module defines the Scanner class responsible for managing the scanning operations.
"""

from typing import List, Dict, Any
import asyncio
from datetime import datetime
import logging
import time
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    SpinnerColumn
)


class Scanner:
    """
    The main scanning engine for Sud0Recon.

    Attributes:
    - targets: A list of targets (IP addresses, domain names, etc.) to scan
    """

    def __init__(
            self,
            targets: List[str],
            comprehensive_vuln_scan: bool = True,
            enable_vuln_scan: bool = True):
        self.targets = targets
        self.results = []
        self.comprehensive_vuln_scan = comprehensive_vuln_scan
        self.enable_vuln_scan = enable_vuln_scan

    async def scan_target(
            self, target: str, comprehensive_vuln_scan: bool = True) -> Dict[str, Any]:
        """Perform comprehensive scanning on a single target."""
        from ..plugins.vuln_scanner import VulnScannerPlugin
        from ..plugins.fast_vuln_scanner import FastVulnScannerPlugin
        from ..plugins.subdomain_enum import SubdomainEnumPlugin
        from ..plugins.port_scanner import PortScannerPlugin

        # Initialize plugins - use comprehensive scanner by default
        if comprehensive_vuln_scan:
            vuln_scanner = VulnScannerPlugin()
        else:
            vuln_scanner = FastVulnScannerPlugin()
        subdomain_scanner = SubdomainEnumPlugin()
        port_scanner = PortScannerPlugin()

        result = {
            "target": target,
            "status": "up",
            "timestamp": datetime.now().isoformat(),
            "scan_type": "comprehensive"
        }

        try:
            # Prepare scan tasks
            scan_tasks = []

            # Add vulnerability scan if enabled
            if self.enable_vuln_scan:
                scan_tasks.append(vuln_scanner.scan(target))
            else:
                # Placeholder for disabled vuln scan
                scan_tasks.append(asyncio.sleep(0))

            scan_tasks.extend([
                subdomain_scanner.scan(target),
                port_scanner.scan(target)
            ])

            # Run all scans concurrently
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            # Unpack results
            vuln_results = scan_results[0] if self.enable_vuln_scan else None
            subdomain_results = scan_results[1] if self.enable_vuln_scan else scan_results[0]
            port_results = scan_results[2] if self.enable_vuln_scan else scan_results[1]

            # Process vulnerability scan results
            if self.enable_vuln_scan and vuln_results is not None and not isinstance(
                    vuln_results, Exception):
                result["vulnerabilities"] = vuln_results.get(
                    "vulnerabilities", [])
                result["vulnerability_count"] = len(result["vulnerabilities"])
                result["security_headers"] = vuln_results.get(
                    "security_headers", {})
                result["ssl_issues"] = vuln_results.get("ssl_issues", [])
                result["cms_detection"] = vuln_results.get("cms_detection", {})
            elif not self.enable_vuln_scan:
                result["vulnerabilities"] = []
                result["vulnerability_count"] = 0
                result["security_headers"] = {}
                result["ssl_issues"] = []
                result["cms_detection"] = {}

            # Process subdomain results
            if not isinstance(subdomain_results, Exception):
                result["subdomains"] = subdomain_results.get(
                    "found_subdomains", [])

            # Process port scan results
            if not isinstance(port_results, Exception):
                result["ports"] = port_results.get("open_ports", [])
                result["port_details"] = {
                    "open": port_results.get("open_ports", []),
                    "closed": port_results.get("closed_ports", []),
                    "filtered": port_results.get("filtered_ports", [])
                }

            # Determine overall status
            if result.get("vulnerabilities") or result.get(
                    "ports") or result.get("subdomains"):
                result["status"] = "vulnerable" if result.get(
                    "vulnerabilities") else "accessible"

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"

        return result

    async def run(self):
        """Run the scanning process on all targets with enhanced real-time progress tracking."""
        logging.info("Starting scan on targets")

        # Calculate total scan steps for accurate progress
        # Each target has multiple phases: initialization, port scan, vuln
        # scan, subdomain enum, finalization
        scan_phases_per_target = 5  # Init, Port, Vuln, Subdomain, Finalize
        total_steps = len(self.targets) * scan_phases_per_target

        # Enhanced progress display with granular step tracking and improved
        # visuals
        progress = Progress(
            SpinnerColumn(
                "dots",
                style="bold cyan"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(
                bar_width=50,
                complete_style="bright_green",
                finished_style="bright_green",
                pulse_style="cyan"),
            TextColumn("[bright_blue]{task.completed}[/bright_blue]/[bright_blue]{task.total}[/bright_blue]"),
            TextColumn("[bright_green]{task.percentage:>5.1f}%[/bright_green]"),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(
                elapsed_when_finished=True),
            TextColumn("•"),
            TextColumn("{task.fields[status]}"),
            expand=False)

        start_time = time.time()

        with progress:
            # Main scanning task with total steps for granular progress
            task_id = progress.add_task(
                "🔍 Scanning targets",
                total=total_steps,
                status="🚀 Initializing scanner..."
            )

            # Brief initialization phase
            await asyncio.sleep(0.5)

            # Track individual target progress
            target_progress = {target: 0 for target in self.targets}
            target_status = {target: "queued" for target in self.targets}

            # Update status to show we're starting
            progress.update(
                task_id, status=f"🚀 Starting {len(self.targets)} concurrent scans...")

            # Create enhanced scan coroutines with progress tracking
            scan_coroutines = []
            for target in self.targets:
                scan_coroutines.append(
                    self._scan_target_with_progress(
                        target,
                        self.comprehensive_vuln_scan,
                        target_progress,
                        target_status,
                        progress,
                        task_id))

            completed_targets = 0
            successful_scans = 0
            failed_scans = 0

            # Process scans as they complete
            for scan_finished in asyncio.as_completed(scan_coroutines):
                try:
                    result = await scan_finished
                    self.results.append(result)
                    completed_targets += 1

                    # Track success/failure
                    if result.get("status") == "error":
                        failed_scans += 1
                    else:
                        successful_scans += 1

                    # Calculate real-time statistics
                    elapsed_time = time.time() - start_time
                    remaining_targets = len(self.targets) - completed_targets

                    # Determine status and icon
                    target = result.get("target", "unknown")
                    status = result.get("status", "unknown")

                    if status == "error":
                        status_icon = "❌"
                        status_text = "Failed"
                    elif status == "vulnerable":
                        status_icon = "⚠️"
                        status_text = "Vulnerable"
                        vuln_count = result.get("vulnerability_count", 0)
                        if vuln_count > 0:
                            status_text += f" ({vuln_count} issues)"
                    elif status == "accessible":
                        status_icon = "✅"
                        status_text = "Clean"
                    else:
                        status_icon = "✅"
                        status_text = "Complete"

                    # Create detailed status display with statistics
                    if remaining_targets > 0:
                        avg_time = elapsed_time / completed_targets if completed_targets > 0 else 0
                        eta = avg_time * remaining_targets

                        # Show current target and overall progress
                        status_display = f"{status_icon} {
                            target[
                                :20]}{
                            '...' if len(target) > 20 else ''} → {status_text} | {remaining_targets} left | ETA: {
                            eta:.0f}s | ✅{successful_scans} ❌{failed_scans}"
                    else:
                        # Final completion status
                        status_display = (
                            f"🎉 All scans completed! ✅ {successful_scans} successful, "
                            f"❌ {failed_scans} failed ({elapsed_time:.1f}s)"
                        )

                        # Update to 100% completion
                        progress.update(task_id, completed=total_steps)

                    # Update progress with current status
                    progress.update(task_id, status=status_display)

                    # Log detailed progress
                    logging.debug(
                        f"Target {target} completed: {status} | "
                        f"Progress: {completed_targets}/{len(self.targets)} targets")

                except Exception as e:
                    # Handle scan errors gracefully
                    error_result = {
                        "target": "unknown",
                        "status": "error",
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                    self.results.append(error_result)
                    completed_targets += 1
                    failed_scans += 1

                    error_msg = str(e)[:30] + \
                        "..." if len(str(e)) > 30 else str(e)
                    progress.update(
                        task_id,
                        status=f"❌ Scan Error: {error_msg} | {len(self.targets) - completed_targets} remaining"
                    )

                    logging.error(f"Error in scan: {e}")

                # Small delay for smooth updates
                await asyncio.sleep(0.05)

            # Final statistics and completion
            total_time = time.time() - start_time

            # Ensure progress shows 100% complete
            progress.update(
                task_id,
                completed=total_steps,
                status=f"🎉 Scan complete! ✅ {successful_scans}/{len(self.targets)} successful in {total_time:.1f}s"
            )

            # Show completion status for a moment
            await asyncio.sleep(2.0)

        logging.info(
            f"Scan completed: {successful_scans}/{len(self.targets)} "
            f"successful in {total_time:.2f} seconds")

    async def _scan_target_with_progress(
            self,
            target,
            comprehensive_vuln_scan,
            target_progress,
            target_status,
            progress,
            task_id):
        """Scan a target with detailed progress tracking for each phase."""
        try:
            target_status[target] = "starting"

            # Phase 1: Initialization
            target_status[target] = "initializing"
            progress.update(
                task_id,
                advance=1,
                status=f"🔧 Initializing scan for {target}...")
            await asyncio.sleep(0.1)

            # Phase 2: Port scanning
            target_status[target] = "port_scanning"
            progress.update(
                task_id,
                advance=1,
                status=f"🔍 Port scanning {target}...")
            port_results = await self._run_port_scan(target)
            await asyncio.sleep(0.1)

            # Phase 3: Vulnerability scanning
            if self.enable_vuln_scan:
                target_status[target] = "vuln_scanning"
                progress.update(
                    task_id,
                    advance=1,
                    status=f"🛡️ Vulnerability scanning {target}...")
                vuln_results = await self._run_vuln_scan(target, comprehensive_vuln_scan)
            else:
                progress.update(
                    task_id,
                    advance=1,
                    status=f"⏭️ Skipping vulnerability scan for {target}...")
                vuln_results = None
            await asyncio.sleep(0.1)

            # Phase 4: Subdomain enumeration
            target_status[target] = "subdomain_enum"
            progress.update(
                task_id,
                advance=1,
                status=f"🌐 Finding subdomains for {target}...")
            subdomain_results = await self._run_subdomain_enum(target)
            await asyncio.sleep(0.1)

            # Phase 5: Finalization
            target_status[target] = "finalizing"
            progress.update(
                task_id,
                advance=1,
                status=f"📝 Finalizing results for {target}...")

            # Compile final result
            result = await self._compile_target_result(target, port_results, vuln_results, subdomain_results)

            target_status[target] = "completed"
            return result

        except Exception as e:
            target_status[target] = "error"
            # Advance remaining steps for this target
            remaining_steps = 5 - target_progress.get(target, 0)
            if remaining_steps > 0:
                progress.update(task_id, advance=remaining_steps)

            return {
                "target": target,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def _compile_target_result(
            self,
            target,
            port_results,
            vuln_results,
            subdomain_results):
        """Compile the final result for a target from all scan components."""
        result = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "comprehensive" if self.comprehensive_vuln_scan else "fast"
        }

        try:
            # Process vulnerability scan results
            if self.enable_vuln_scan and vuln_results is not None and not isinstance(
                    vuln_results, Exception):
                result["vulnerabilities"] = vuln_results.get(
                    "vulnerabilities", [])
                result["vulnerability_count"] = len(result["vulnerabilities"])
                result["security_headers"] = vuln_results.get(
                    "security_headers", {})
                result["ssl_issues"] = vuln_results.get("ssl_issues", [])
                result["cms_detection"] = vuln_results.get("cms_detection", {})
            elif not self.enable_vuln_scan:
                result["vulnerabilities"] = []
                result["vulnerability_count"] = 0
                result["security_headers"] = {}
                result["ssl_issues"] = []
                result["cms_detection"] = {}

            # Process subdomain results
            if not isinstance(subdomain_results, Exception):
                result["subdomains"] = subdomain_results.get(
                    "found_subdomains", [])

            # Process port scan results
            if not isinstance(port_results, Exception):
                result["ports"] = port_results.get("open_ports", [])
                result["port_details"] = {
                    "open": port_results.get("open_ports", []),
                    "closed": port_results.get("closed_ports", []),
                    "filtered": port_results.get("filtered_ports", [])
                }

            # Determine overall status
            if result.get("vulnerabilities") or result.get(
                    "ports") or result.get("subdomains"):
                result["status"] = "vulnerable" if result.get(
                    "vulnerabilities") else "accessible"

        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"

        return result

    async def _run_port_scan(self, target):
        """Run port scanning for a target."""
        try:
            from ..plugins.port_scanner import PortScannerPlugin
            port_scanner = PortScannerPlugin()
            return await port_scanner.scan(target)
        except Exception as e:
            logging.error(f"Port scan failed for {target}: {e}")
            return {
                "error": str(e),
                "open_ports": [],
                "closed_ports": [],
                "filtered_ports": []}

    async def _run_vuln_scan(self, target, comprehensive=True):
        """Run vulnerability scanning for a target."""
        try:
            if comprehensive:
                from ..plugins.vuln_scanner import VulnScannerPlugin
                vuln_scanner = VulnScannerPlugin()
            else:
                from ..plugins.fast_vuln_scanner import FastVulnScannerPlugin
                vuln_scanner = FastVulnScannerPlugin()
            return await vuln_scanner.scan(target)
        except Exception as e:
            logging.error(f"Vulnerability scan failed for {target}: {e}")
            return {
                "error": str(e),
                "vulnerabilities": [],
                "security_headers": {},
                "ssl_issues": [],
                "cms_detection": {}}

    async def _run_subdomain_enum(self, target):
        """Run subdomain enumeration for a target."""
        try:
            from ..plugins.subdomain_enum import SubdomainEnumPlugin
            subdomain_scanner = SubdomainEnumPlugin()
            return await subdomain_scanner.scan(target)
        except Exception as e:
            logging.error(f"Subdomain enumeration failed for {target}: {e}")
            return {"error": str(e), "found_subdomains": []}

    def get_results(self) -> List[Dict[str, Any]]:
        """Return the scan results."""
        return self.results

    def save_results(self, format: str):
        """Save scan results to a file in the specified format (e.g., JSON, HTML)."""
        if format == "json":
            self.save_as_json()
        elif format == "html":
            self.save_as_html()
        else:
            raise ValueError("Unsupported format")

    def save_as_json(self) -> str:
        """Save results in JSON format and return the file path."""
        import json
        import os
        import re
        from datetime import datetime

        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

        # Generate timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create target-based filename
        if self.targets:
            # Clean target names for filename (remove special characters)
            cleaned_targets = []
            for target in self.targets:
                # Remove protocol prefixes and clean special characters
                clean_target = re.sub(r'^https?://', '', target)
                clean_target = re.sub(r'[^a-zA-Z0-9.-]', '_', clean_target)
                cleaned_targets.append(clean_target)

            # Create target part of filename
            if len(cleaned_targets) == 1:
                target_part = cleaned_targets[0]
            elif len(cleaned_targets) <= 3:
                target_part = "_".join(cleaned_targets)
            else:
                # For many targets, use first target + count
                target_part = f"{
                    cleaned_targets[0]}_and_{
                    len(cleaned_targets) -
                    1}_more"

            # Limit target part length to avoid overly long filenames
            if len(target_part) > 50:
                target_part = target_part[:47] + "..."

            filename = f"sud0recon_scan_{target_part}_{timestamp}.json"
        else:
            # Fallback to timestamp only if no targets
            filename = f"sud0recon_scan_{timestamp}.json"

        filepath = os.path.join(reports_dir, filename)

        # Prepare scan data
        scan_data = {
            "scan_metadata": {
                "scan_id": f"sud0recon_{timestamp}",
                "timestamp": datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "targets_count": len(self.targets),
                "results_count": len(self.results)
            },
            "targets": self.targets,
            "results": self.results,
            "generated_by": "Sud0Recon v1.0.0",
            "contact": "sud0x.dev@proton.me"
        }

        # Save to JSON file
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)

        logging.info(f"Results saved to: {filepath}")
        return filepath

    def save_as_html(self):
        """Save results in HTML format."""
        logging.info("Saving results as HTML")
        # Implementation needed
