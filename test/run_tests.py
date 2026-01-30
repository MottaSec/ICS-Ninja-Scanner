#!/usr/bin/env python3
"""
Test runner for the MottaSec ICS Ninja Scanner.
Provides a user-friendly output format for test results.

Created by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import os
import sys
import unittest
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Initialize console
console = Console()

def print_mottasec_banner():
    """Print the MottaSec ICS Ninja Scanner Test Suite banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║  [bold blue]MottaSec ICS Ninja Scanner - Test Suite[/bold blue]                              ║
    ║                                                                              ║
    ║  [cyan]Developed by the MottaSec Ghost Team[/cyan]                                   ║
    ║  [cyan]The unseen guardians of industrial systems[/cyan]                             ║
    ║                                                                              ║
    ║  [green]"We test what others miss"[/green]                                           ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, border_style="blue"))

class MottaSecTextTestResult(unittest.TextTestResult):
    """Custom test result class for better output formatting."""
    
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.successes = []
        self.tests_run = []
        self.start_time = time.time()
        
    def startTest(self, test):
        super().startTest(test)
        self.tests_run.append(test)
        
    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)

def run_tests():
    """Run all tests and display results in a user-friendly format."""
    print_mottasec_banner()
    
    start_time = time.time()
    
    # Discover all tests
    test_loader = unittest.defaultTestLoader
    # Explicitly specify the test directory and pattern to avoid importing from scanners
    test_suite = test_loader.discover(
        start_dir=os.path.dirname(__file__), 
        pattern='test_*.py',
        top_level_dir=os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    )
    
    # Count total tests for progress bar
    total_tests = 0
    for suite in test_suite:
        for test_case in suite:
            total_tests += test_case.countTestCases()
    
    # Create a custom test runner with our result class
    test_runner = unittest.TextTestRunner(resultclass=MottaSecTextTestResult, verbosity=0)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        # Create a progress bar
        task = progress.add_task("[bold blue]Running tests...", total=total_tests)
        
        # Redirect stdout to capture test output
        original_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        
        # Run tests
        result = test_runner.run(test_suite)
        
        # Restore stdout
        sys.stdout.close()
        sys.stdout = original_stdout
        
        # Update progress bar to completion
        progress.update(task, completed=total_tests)
    
    # Calculate test duration
    duration = time.time() - start_time
    
    # Create summary table
    table = Table(title="Test Results Summary", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="white")
    table.add_column("Status", style="white")
    
    # Add rows with test counts
    table.add_row("Total Tests", str(result.testsRun), "")
    table.add_row("Passed", str(len(result.successes)), "[green]✓[/green]")
    table.add_row("Failed", str(len(result.failures)), 
                 "[red]✗[/red]" if result.failures else "[green]✓[/green]")
    table.add_row("Errors", str(len(result.errors)), 
                 "[red]✗[/red]" if result.errors else "[green]✓[/green]")
    table.add_row("Skipped", str(len(result.skipped)), 
                 "[yellow]![/yellow]" if result.skipped else "")
    
    # Print summary table
    console.print()
    console.print(table)
    console.print(f"\n[bold]Test Suite completed in [cyan]{duration:.2f}[/cyan] seconds[/bold]\n")
    
    # Display failures and errors in detail if any
    if result.failures or result.errors:
        console.print("[bold red]Issues Found:[/bold red]")
        
        if result.failures:
            console.print("\n[bold yellow]Failures:[/bold yellow]")
            for i, (test, traceback) in enumerate(result.failures):
                module_name = test.__class__.__module__
                class_name = test.__class__.__name__
                method_name = test._testMethodName
                
                console.print(f"[red]{i+1}. {module_name}.{class_name}.{method_name}[/red]")
                console.print(f"   [dim]{test._testMethodDoc}[/dim]")
                
                # Extract and print the relevant part of the traceback
                error_lines = traceback.split('\n')
                error_message = next((line for line in error_lines if "AssertionError" in line), "")
                if error_message:
                    console.print(f"   [yellow]Error: {error_message.strip()}[/yellow]")
                else:
                    console.print(f"   [yellow]See full traceback below[/yellow]")
                
                console.print()
        
        if result.errors:
            console.print("\n[bold yellow]Errors:[/bold yellow]")
            for i, (test, traceback) in enumerate(result.errors):
                module_name = test.__class__.__module__
                class_name = test.__class__.__name__
                method_name = test._testMethodName
                
                console.print(f"[red]{i+1}. {module_name}.{class_name}.{method_name}[/red]")
                console.print(f"   [dim]{test._testMethodDoc}[/dim]")
                
                # Extract and print the relevant part of the traceback
                error_lines = traceback.split('\n')
                error_message = next((line for line in error_lines if "Error:" in line or "Exception:" in line), "")
                if error_message:
                    console.print(f"   [yellow]Error: {error_message.strip()}[/yellow]")
                else:
                    console.print(f"   [yellow]See full traceback below[/yellow]")
                
                console.print()
        
        # Print full tracebacks in debug section
        console.print("\n[bold blue]Detailed Error Information:[/bold blue]")
        console.print("[dim]This section contains full tracebacks for debugging.[/dim]\n")
        
        if result.failures:
            console.print("[bold]Failure Tracebacks:[/bold]")
            for i, (test, traceback) in enumerate(result.failures):
                console.print(f"[bold]{i+1}. {test}[/bold]")
                console.print(f"[dim]{traceback}[/dim]\n")
        
        if result.errors:
            console.print("[bold]Error Tracebacks:[/bold]")
            for i, (test, traceback) in enumerate(result.errors):
                console.print(f"[bold]{i+1}. {test}[/bold]")
                console.print(f"[dim]{traceback}[/dim]\n")
    
    # Print recommendations for fixing issues
    if result.failures or result.errors:
        console.print("\n[bold green]Recommendations:[/bold green]")
        
        # MQTT scanner issues
        if any("mqtt" in str(test).lower() for test, _ in result.errors):
            console.print("[yellow]• MQTT Scanner Issues:[/yellow] Update the MQTT scanner to use the correct callback API version for paho-mqtt 2.0+")
            console.print("  All MQTT client instantiations need the callback_api_version parameter")
        
        # validate_protocols_all issues
        if any("validate_protocols_all" in str(test) for test, _ in result.errors):
            console.print("[yellow]• Protocol Validation Issues:[/yellow] Fix the test_validate_protocols_all test to properly mock the Click context")
        
        # cli_scan_basic issues
        if any("cli_scan_basic" in str(test) for test, _ in result.failures):
            console.print("[yellow]• CLI Scan Test Issues:[/yellow] Ensure the mock scanner instance is being called correctly in test_cli_scan_basic")
    
    # Return exit code based on test results
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(run_tests()) 