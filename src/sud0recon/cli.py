"""
Command Line Interface for Sud0Recon

This module provides the CLI functionality for Sud0Recon scanner.
"""

import argparse
import asyncio
import sys
import random
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.tree import Tree
from .core.scanner import Scanner

console = Console()


def create_banner() -> Panel:
    """Create an enhanced and attractive Sud0Recon banner with random colors."""
    # Get terminal width for responsive design
    try:
        terminal_width = console.size.width
    except Exception:
        terminal_width = 120  # Default fallback width
    # Available color schemes - each run will randomly select one
    color_schemes = [
        {
            'main_colors': ['bold bright_red', 'bright_red', 'red'],
            'accent': 'bright_cyan',
            'border': 'bright_cyan',
            'theme': 'Classic Red Hacker'
        },
        {
            'main_colors': ['bold bright_green', 'bright_green', 'green'],
            'accent': 'bright_yellow',
            'border': 'bright_green',
            'theme': 'Matrix Green'
        },
        {
            'main_colors': ['bold bright_blue', 'bright_blue', 'blue'],
            'accent': 'bright_cyan',
            'border': 'bright_blue',
            'theme': 'Ocean Blue'
        },
        {
            'main_colors': ['bold bright_magenta', 'bright_magenta', 'magenta'],
            'accent': 'bright_white',
            'border': 'bright_magenta',
            'theme': 'Neon Purple'
        },
        {
            'main_colors': ['bold bright_yellow', 'yellow', 'bright_yellow'],
            'accent': 'bright_red',
            'border': 'bright_yellow',
            'theme': 'Electric Gold'
        },
        {
            'main_colors': ['bold bright_cyan', 'cyan', 'bright_cyan'],
            'accent': 'bright_white',
            'border': 'bright_cyan',
            'theme': 'Cyber Cyan'
        },
        {
            'main_colors': ['bold white', 'bright_white', 'white'],
            'accent': 'bright_blue',
            'border': 'bright_white',
            'theme': 'Clean Terminal'
        },
        {
            'main_colors': [
                'bold rgb(255,165,0)', 'rgb(255,140,0)', 'rgb(255,69,0)'
            ],
            'accent': 'bright_yellow',
            'border': 'rgb(255,165,0)',
            'theme': 'Fire Orange'
        }
    ]

    # Randomly select a color scheme
    scheme = random.choice(color_schemes)

    # Create ASCII art with colors and centering
    panel_width = min(terminal_width, 150)
    content_width = panel_width - 4  # Account for panel padding

    # Choose appropriate ASCII art based on available width
    if content_width >= 90:  # Full ASCII art (need extra space for centering)
        ascii_lines = [
            "███████ ██    ██ ██████   ██████  ██████  ███████  ██████  ██████  ███    ██",
            "██      ██    ██ ██   ██ ██  ████ ██   ██ ██      ██      ██  ████ ████   ██",
            "███████ ██    ██ ██   ██ ██ ██ ██ ██████  █████   ██      ██ ██ ██ ██ ██  ██",
            "     ██ ██    ██ ██   ██ ████  ██ ██   ██ ██      ██      ████  ██ ██  ██ ██",
            "███████  ██████  ██████   ██████  ██   ██ ███████  ██████  ██████  ██   ████"]
    elif content_width >= 60:  # Medium ASCII art
        ascii_lines = [
            "███████ ██    ██ ██████   ██████  ██████  ███████",
            "██      ██    ██ ██   ██ ██  ████ ██   ██ ██     ",
            "███████ ██    ██ ██   ██ ██ ██ ██ ██████  █████  ",
            "     ██ ██    ██ ██   ██ ████  ██ ██   ██ ██     ",
            "███████  ██████  ██████   ██████  ██   ██ ███████"
        ]
    elif content_width >= 42:  # Compact ASCII art
        ascii_lines = [
            "███ █   █ ███ █████  █████ █   █ ███",
            " █  ██  █ █      █     █   █ █   █ ",
            " █  █ █ █ ███    █     █   ██    █ ",
            " █  █  ██   █    █     █   █ █   █ ",
            "███ █   █ ███    █     █   █   ███"
        ]
    elif content_width >= 30:  # Simple text banner
        ascii_lines = [
            "▄▄▄ ▄   ▄ ▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄   ▄ ▄▄▄",
            " █  ██  █ █  █  █     █   █ █   █ █  ",
            " █  █ █ █ █▄▄█  █     █   ██ ▄▄▄ █  ",
            " █  █  ██ █  █  █     █   █ █   █ █  ",
            "▄▄▄ █   █ █  █  █     █   █ █   █ ▄▄▄"
        ]
    elif content_width >= 20:  # Very compact
        ascii_lines = [
            "SUD0-RECON",
            "═══════════",
            "Security Scanner"
        ]
    else:  # Minimal
        ascii_lines = [
            "SUD0RECON",
            "Scanner"
        ]

    # Create banner content
    banner_content = Text()
    banner_content.append("\n")

    # Add centered ASCII art
    for i, line in enumerate(ascii_lines):
        padding = max(0, (content_width - len(line)) // 2)
        centered_line = ' ' * padding + line
        color_style = scheme['main_colors'][0] if i in [
            0, 4] else scheme['main_colors'][1] if i in [
            1, 3] else scheme['main_colors'][2]
        banner_content.append(centered_line, style=color_style)
        banner_content.append("\n")

    # Add spacing and subtitle
    banner_content.append("\n")
    subtitle = "🔍 Advanced Reconnaissance & Security Scanner"
    subtitle_padding = max(0, (content_width - len(subtitle)) // 2)
    centered_subtitle = ' ' * subtitle_padding + subtitle
    banner_content.append(centered_subtitle, style=f"bold {scheme['accent']}")
    banner_content.append("\n")

    # Add theme indicator
    theme_text = f"✨ {scheme['theme']} Theme"
    theme_padding = max(0, (content_width - len(theme_text)) // 2)
    centered_theme = ' ' * theme_padding + theme_text
    banner_content.append(
        centered_theme, style=f"dim {
            scheme['main_colors'][2]}")
    banner_content.append("\n\n")

    # Add version and info line
    info_text = "🚀 v1.0.0  •  👨‍💻 Sud0-x  •  🛡️ Pentest Ready"
    info_padding = max(0, (content_width - len(info_text)) // 2)
    banner_content.append(' ' * info_padding, style="")
    banner_content.append("🚀 ", style="bright_yellow")
    banner_content.append("v1.0.0", style=f"bold {scheme['main_colors'][1]}")
    banner_content.append("  •  ", style="dim white")
    banner_content.append("👨‍💻 ", style=scheme['accent'])
    banner_content.append("Sud0-x", style=f"bold {scheme['accent']}")
    banner_content.append("  •  ", style="dim white")
    banner_content.append("🛡️ ", style="bright_yellow")
    banner_content.append(
        "Pentest Ready", style=f"bold {
            scheme['main_colors'][0]}")
    banner_content.append("\n")

    # Create responsive subtitle
    panel_subtitle = "📧 sud0x.dev@proton.me  •  🌐 github.com/Sud0-x/Sud0Recon  •  ⭐ Made for Security Professionals"
    if terminal_width < 120:
        panel_subtitle = "📧 sud0x.dev@proton.me  •  🌐 github.com/Sud0-x/Sud0Recon"
    if terminal_width < 80:
        panel_subtitle = "📧 sud0x.dev@proton.me"

    return Panel(
        banner_content,
        border_style=scheme['border'],
        padding=(0, 1),
        subtitle=f"[dim {scheme['accent']}]{panel_subtitle}[/dim {scheme['accent']}]",
        subtitle_align="center",
        width=panel_width
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="sud0recon",
        description="Sud0Recon - Next-level automated reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sud0recon -t example.com                    # Scan single target (shows results in terminal)
  sud0recon -t example.com,google.com         # Scan multiple targets
  sud0recon -t example.com -A                 # Aggressive scan (all scan types enabled)
  sud0recon -t example.com -o json,html       # Generate JSON and HTML reports
  sud0recon -t example.com --threads 100      # Use 100 concurrent threads
  sud0recon -t example.com --timeout 60       # Set 60 second timeout
  sud0recon -t example.com --no-terminal      # Skip terminal output, save to file only

For more information, visit: https://github.com/Sud0-x/Sud0Recon
Contact: sud0x.dev@proton.me
        """
    )

    # Target specification
    parser.add_argument(
        "-t", "--targets",
        required=True,
        help="Target(s) to scan (comma-separated for multiple)"
    )

    # Scanning options
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Scan timeout in seconds (default: 30)"
    )

    # Output options
    parser.add_argument(
        "-o", "--output",
        default="json",
        help="Output format(s): json,html,console (default: json)"
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)"
    )

    # Scan types
    parser.add_argument(
        "--subdomain-enum",
        action="store_true",
        help="Enable subdomain enumeration"
    )

    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Enable port scanning"
    )

    parser.add_argument(
        "--banner-grab",
        action="store_true",
        help="Enable banner grabbing"
    )

    parser.add_argument(
        "--vuln-scan",
        action="store_true",
        default=True,
        help="Enable vulnerability scanning (enabled by default)"
    )

    parser.add_argument(
        "--fast-vuln",
        action="store_true",
        help="Use fast vulnerability scanning instead of comprehensive"
    )

    parser.add_argument(
        "--no-vuln",
        action="store_true",
        help="Disable vulnerability scanning"
    )

    # Aggressive scan option
    parser.add_argument(
        "-A", "--aggressive",
        action="store_true",
        help="Aggressive scan (enables all scan types: subdomain-enum, port-scan, banner-grab, vuln-scan)"
    )

    # Utility options
    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )

    parser.add_argument(
        "--no-terminal",
        action="store_true",
        help="Skip terminal output, save to file only"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Sud0Recon v1.0.0"
    )

    return parser.parse_args()


def parse_targets(targets_str: str) -> List[str]:
    """Parse comma-separated targets string into a list."""
    return [target.strip()
            for target in targets_str.split(",") if target.strip()]


def display_results_in_terminal(
        results: List[dict],
        targets: List[str]) -> None:
    """Display scan results in the terminal with beautiful formatting."""
    from datetime import datetime

    console.print("\n" + "=" * 60)
    console.print("[bold cyan]📊 SCAN RESULTS[/bold cyan]", justify="center")
    console.print("=" * 60)

    # Summary table
    summary_table = Table(
        title="\n🎯 Scan Summary",
        show_header=True,
        header_style="bold blue")
    summary_table.add_column("Metric", style="cyan", justify="left")
    summary_table.add_column("Value", style="green", justify="center")

    summary_table.add_row("Targets Scanned", str(len(targets)))
    summary_table.add_row("Results Found", str(len(results)))
    summary_table.add_row(
        "Success Rate", f"{(len(results) / len(targets) * 100):.1f}%" if targets else "0%")
    summary_table.add_row(
        "Scan Time",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    console.print(summary_table)

    # Detailed results
    if results:
        console.print("\n[bold yellow]📋 Detailed Results:[/bold yellow]")

        for i, result in enumerate(results, 1):
            # Create a panel for each result
            target = result.get('target', 'Unknown')
            status = result.get('status', 'Unknown')
            timestamp = result.get('timestamp', 'Unknown')

            # Status color
            status_color = "green" if status.lower(
            ) == "up" else "red" if status.lower() == "down" else "yellow"

            result_tree = Tree(f"[bold]Target #{i}: [cyan]{target}[/cyan]")
            result_tree.add(
                f"[{status_color}]Status: {status.upper()}[/{status_color}]")
            result_tree.add(f"[blue]Timestamp: {timestamp}[/blue]")

            # Add more detailed info if available
            if 'ports' in result:
                ports_node = result_tree.add(
                    "[yellow]🔍 Port Information[/yellow]")
                if result['ports']:
                    for port_info in result['ports']:
                        ports_node.add(f"Port {port_info}: Open")
                else:
                    ports_node.add("No open ports found")

            if 'subdomains' in result:
                subdomain_node = result_tree.add(
                    "[purple]🌐 Subdomains[/purple]")
                if result['subdomains']:
                    for subdomain in result['subdomains']:
                        subdomain_node.add(f"• {subdomain}")
                else:
                    subdomain_node.add("No subdomains found")

            if 'vulnerabilities' in result:
                vulns = result['vulnerabilities']
                vuln_node = result_tree.add("[red]🛡️ Vulnerabilities[/red]")
                if vulns:
                    # Group by severity
                    critical = [
                        v for v in vulns if v.get('severity') == 'CRITICAL']
                    high = [v for v in vulns if v.get('severity') == 'HIGH']
                    medium = [
                        v for v in vulns if v.get('severity') == 'MEDIUM']
                    low = [v for v in vulns if v.get('severity') == 'LOW']

                    if critical:
                        crit_node = vuln_node.add(
                            f"[red]🔴 CRITICAL ({len(critical)})[/red]")
                        for vuln in critical[:3]:  # Show max 3 per category
                            crit_node.add(
                                f"⚠️ {
                                    vuln.get(
                                        'title',
                                        'Unknown vulnerability')}")

                    if high:
                        high_node = vuln_node.add(
                            f"[yellow]🟠 HIGH ({len(high)})[/yellow]")
                        for vuln in high[:3]:
                            high_node.add(
                                f"⚠️ {
                                    vuln.get(
                                        'title',
                                        'Unknown vulnerability')}")

                    if medium:
                        med_node = vuln_node.add(
                            f"[blue]🟡 MEDIUM ({len(medium)})[/blue]")
                        for vuln in medium[:2]:
                            med_node.add(
                                f"⚠️ {
                                    vuln.get(
                                        'title',
                                        'Unknown vulnerability')}")

                    if low:
                        low_node = vuln_node.add(
                            f"[dim]⚪ LOW ({len(low)})[/dim]")
                        if low:
                            if len(low) > 1:
                                low_node.add(
                                    f"ℹ️ {low[0].get('title', 'Unknown vulnerability')} (+{len(low) - 1} more)")
                            else:
                                low_node.add(
                                    f"ℹ️ {
                                        low[0].get(
                                            'title',
                                            'Unknown vulnerability')}")

                    vuln_node.add(
                        f"[dim]Total: {
                            len(vulns)} vulnerabilities found[/dim]")
                else:
                    vuln_node.add(
                        "[green]✅ No vulnerabilities detected[/green]")

            console.print(result_tree)
            console.print()  # Add spacing

    else:
        console.print("\n[yellow]⚠️ No results to display[/yellow]")

    # Footer
    console.print("[dim]" + "=" * 60 + "[/dim]")
    console.print("[bold green]✅ Terminal display complete![/bold green]")
    console.print(
        "[dim]Results are also saved to JSON file for detailed analysis.[/dim]")


async def run_scan(args: argparse.Namespace) -> None:
    """Run the main scanning process."""
    targets = parse_targets(args.targets)

    # Handle aggressive scan option
    if args.aggressive:
        console.print("[bold red]🔥 AGGRESSIVE SCAN MODE ENABLED[/bold red]")
        console.print(
            "[yellow]Automatically enabling all scan types:[/yellow]")
        console.print("  • Subdomain enumeration: ON")
        console.print("  • Port scanning: ON")
        console.print("  • Banner grabbing: ON")
        console.print("  • Vulnerability scanning: ON")
        console.print()

        # Override individual scan options when aggressive mode is enabled
        args.subdomain_enum = True
        args.port_scan = True
        args.banner_grab = True
        args.vuln_scan = True
        args.no_vuln = False  # Ensure vuln scanning is not disabled

    console.print(
        f"\n[bold green]Scanning {
            len(targets)} target(s):[/bold green]")
    for target in targets:
        console.print(f"  • {target}", style="cyan")

    console.print("\n[bold yellow]Configuration:[/bold yellow]")
    console.print(f"  • Threads: {args.threads}")
    console.print(f"  • Timeout: {args.timeout}s")
    console.print(f"  • Output: {args.output}")

    # Display enabled scan types
    scan_types = []
    if args.subdomain_enum:
        scan_types.append("subdomain-enum")
    if args.port_scan:
        scan_types.append("port-scan")
    if args.banner_grab:
        scan_types.append("banner-grab")
    if args.vuln_scan and not args.no_vuln:
        scan_types.append("vuln-scan")

    if scan_types:
        console.print(f"  • Enabled Scans: {', '.join(scan_types)}")
    else:
        console.print("  • Enabled Scans: basic connectivity only")

    # Determine vulnerability scanning mode
    if args.no_vuln:
        vuln_scan_mode = "disabled"
        comprehensive_vuln = False
    elif args.fast_vuln:
        vuln_scan_mode = "fast"
        comprehensive_vuln = False
    else:
        vuln_scan_mode = "comprehensive"
        comprehensive_vuln = True

    console.print(f"  • Vulnerability Scan: {vuln_scan_mode}")
    console.print()

    # Initialize and run scanner
    scanner = Scanner(
        targets,
        comprehensive_vuln_scan=comprehensive_vuln,
        enable_vuln_scan=not args.no_vuln
    )
    await scanner.run()

    # Display results
    results = scanner.get_results()
    console.print(
        f"\n[bold green]Scan completed! Found {
            len(results)} results.[/bold green]")

    # Display results in terminal (unless --no-terminal is specified)
    if not args.no_terminal:
        display_results_in_terminal(results, targets)
    else:
        console.print(
            "[dim]Terminal output skipped (--no-terminal specified)[/dim]")

    # Save results
    for format_type in args.output.split(","):
        format_type = format_type.strip()
        if format_type:
            try:
                if format_type.lower() == "json":
                    filepath = scanner.save_as_json()
                    import os
                    absolute_path = os.path.abspath(filepath)

                    console.print(
                        "[green]✓[/green] Results saved in JSON format")
                    console.print(
                        f"[cyan]📁 File location: {absolute_path}[/cyan]")
                    console.print(
                        "[dim]   (File named with target for easy identification)[/dim]")
                    console.print(
                        f"[yellow]💡 Quick view: cat {filepath}[/yellow]")
                    console.print(
                        f"[yellow]💡 Open in editor: nano {filepath}[/yellow]")
                    console.print(
                        "[yellow]💡 View latest: ./view-report.sh[/yellow]")
                else:
                    scanner.save_results(format_type)
                    console.print(
                        f"[green]✓[/green] Results saved in {format_type.upper()} format")
            except ValueError as e:
                console.print(f"[red]✗[/red] {e}")


def main() -> None:
    """Main entry point for the CLI."""
    try:
        # Display banner
        console.print(create_banner())

        # Parse arguments
        args = parse_arguments()

        # Run the scanner
        asyncio.run(run_scan(args))

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
