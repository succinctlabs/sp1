#!/usr/bin/env python3
import subprocess
import os
from datetime import datetime
import argparse
from pathlib import Path
from bs4 import BeautifulSoup
import re

class RustBuildProfiler:
    def __init__(self, project_path="."):
        self.project_path = Path(project_path)
        self.timings_dir = self.project_path / "target" / "cargo-timings"
    
    def run_build_with_timing(self):
        """Run cargo build with timing flags enabled"""
        print("Running cargo build with timing enabled...")
        cmd = [
            "cargo", "build",
            "--timings",
            "--release",  # Optional: change to debug if needed
            "--package", "sp1-sdk"
        ]
        
        try:
            subprocess.run(cmd, cwd=self.project_path, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running cargo build: {e}")
            return False
        return True

    def get_latest_timing_file(self):
        """Get the most recent timing HTML file"""
        if not self.timings_dir.exists():
            return None
            
        timing_files = list(self.timings_dir.glob("cargo-timing-*.html"))
        if not timing_files:
            return None
            
        return max(timing_files, key=lambda f: f.stat().st_mtime)

    def parse_duration(self, duration_str):
        """Parse duration string to seconds"""
        if 'ms' in duration_str:
            return float(duration_str.replace('ms', '')) / 1000
        elif 's' in duration_str:
            return float(duration_str.replace('s', ''))
        return 0

    def analyze_timings(self, timing_file):
        """Analyze the timing data from HTML and return formatted results"""
        with open(timing_file) as f:
            soup = BeautifulSoup(f, 'html.parser')

        # Find all timing entries
        unit_times = []
        
        # Look for timing data in the HTML
        # First try the newer cargo timing format
        timing_divs = soup.find_all('div', class_='artifact')
        if timing_divs:
            for div in timing_divs:
                name_elem = div.find('a', class_='name')
                time_elem = div.find('span', class_='time')
                
                if name_elem and time_elem:
                    name = name_elem.text.strip()
                    duration_str = time_elem.text.strip()
                    duration = self.parse_duration(duration_str)
                    unit_times.append((duration, name))
        else:
            # Fall back to older format
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows[1:]:  # Skip header row
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        name = cols[0].text.strip()
                        duration_str = cols[1].text.strip()
                        duration = self.parse_duration(duration_str)
                        unit_times.append((duration, name))

        # Sort by duration (descending)
        unit_times.sort(reverse=True)

        # Calculate total build time
        total_time = sum(duration for duration, _ in unit_times)

        return unit_times, total_time

    def format_duration(self, duration):
        """Format duration in seconds to a human-readable string"""
        if duration < 1:
            return f"{duration*1000:.1f}ms"
        return f"{duration:.2f}s"

    def run_profile(self):
        """Run the complete profiling process"""
        if not self.run_build_with_timing():
            return

        timing_file = self.get_latest_timing_file()
        if not timing_file:
            print("No timing files found. Make sure the build completed successfully.")
            return

        unit_times, total_time = self.analyze_timings(timing_file)

        # Print results
        print("\nBuild Time Analysis")
        print("=" * 60)
        print(f"Total Build Time: {self.format_duration(total_time)}")
        print("\nTop 10 Longest Building Units:")
        print("-" * 60)
        print(f"{'Duration':>12} | {'% of Total':>10} | Unit Name")
        print("-" * 60)

        for duration, name in unit_times[:10]:
            percentage = (duration / total_time) * 100
            print(f"{self.format_duration(duration):>12} | {percentage:>9.1f}% | {name}")

        print(f"\nFull report available at: {timing_file}")

def main():
    parser = argparse.ArgumentParser(description="Profile Rust project build times")
    parser.add_argument("--path", default=".", help="Path to Rust project (default: current directory)")
    args = parser.parse_args()

    profiler = RustBuildProfiler(args.path)
    profiler.run_profile()

if __name__ == "__main__":
    main()