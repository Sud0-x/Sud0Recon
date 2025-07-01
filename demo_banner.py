#!/usr/bin/env python3
"""
Demo script to showcase all Sud0Recon banner themes
"""

import sys
import os
import time

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rich.console import Console
from sud0recon.cli import create_banner
import random

console = Console()

def demo_all_themes():
    """Demo all available banner themes"""
    
    # Get all color schemes from the banner function
    # We'll temporarily modify the random selection to show all themes
    themes = [
        'Classic Red Hacker',
        'Matrix Green', 
        'Ocean Blue',
        'Neon Purple',
        'Electric Gold',
        'Cyber Cyan',
        'Clean Terminal',
        'Fire Orange'
    ]
    
    console.print("[bold yellow]🎨 Sud0Recon Banner Theme Demo[/bold yellow]")
    console.print("[dim]Showcasing all 8 available color themes...[/dim]\n")
    
    for i, theme in enumerate(themes, 1):
        console.print(f"[bold cyan]Theme {i}/{len(themes)}: {theme}[/bold cyan]")
        console.print("─" * 50)
        
        # Display the banner (it will pick a random theme)
        banner = create_banner()
        console.print(banner)
        
        if i < len(themes):
            console.print("\n[dim]Press Enter for next theme...[/dim]")
            input()
            console.clear()
    
    console.print("\n[bold green]✨ Demo Complete![/bold green]")
    console.print("[dim]Each time you run Sud0Recon, one of these themes will be randomly selected![/dim]")

if __name__ == "__main__":
    try:
        demo_all_themes()
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
        sys.exit(0)
