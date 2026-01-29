#!/usr/bin/env python3
import sys
import re
from statistics import mean, median

def parse_time_value(time_str):
    """
    Parse a time string like '11.8ms', '500µs', or '1000ns' and convert to milliseconds.
    """
    # Pattern to match number and unit
    match = re.match(r'([\d.]+)(ms|µs|us|ns|s)', time_str)
    if not match:
        return None
    
    value = float(match.group(1))
    unit = match.group(2)
    
    # Convert to milliseconds
    if unit == 'ms':
        return value
    elif unit in ['µs', 'us']:  # Support both µs and us for microseconds
        return value / 1000.0
    elif unit == 'ns':
        return value / 1000000.0
    elif unit == 's':
        return value * 1000.0
    
    return None

def strip_ansi_codes(text):
    """
    Remove ANSI escape codes from text (equivalent to sed 's/\x1b\[[0-9;]*m//g').
    """
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def parse_log_line(line, prefix_filter=None):
    """
    Parse a log line and extract time.busy and time.idle values.
    Returns a tuple (busy_ms, idle_ms) or None if parsing fails.

    Args:
        line: The log line to parse
        prefix_filter: Optional text that should match the pattern "prefix_filter: close".
                      If provided, only lines matching this exact pattern will be parsed.
    """
    # Strip ANSI escape codes first
    clean_line = strip_ansi_codes(line)

    # If prefix_filter is provided, check for exact pattern "prefix_filter: close"
    if prefix_filter:
        # Look for pattern: prefix_filter: close
        pattern = re.escape(prefix_filter) + r':\s+close\b'
        if not re.search(pattern, clean_line):
            return None

    # Pattern to match time.busy and time.idle values with units
    busy_pattern = r'time\.busy=([\d.]+(?:ms|µs|us|ns|s))'
    idle_pattern = r'time\.idle=([\d.]+(?:ms|µs|us|ns|s))'

    busy_match = re.search(busy_pattern, clean_line)
    idle_match = re.search(idle_pattern, clean_line)

    if busy_match and idle_match:
        busy_ms = parse_time_value(busy_match.group(1))
        idle_ms = parse_time_value(idle_match.group(1))

        if busy_ms is not None and idle_ms is not None:
            return (busy_ms, idle_ms)

    return None

def calculate_statistics(values):
    """
    Calculate mean, median, and range for a list of values.
    """
    if not values:
        return None
    
    return {
        'mean': mean(values),
        'median': median(values),
        'min': min(values),
        'max': max(values),
        'stddev': (mean((x - mean(values))**2 for x in values))**0.5,
        'range': max(values) - min(values)
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python parser.py <log_file> [prefix_filter]")
        print("  log_file:      Path to the log file to parse")
        print("  prefix_filter: Optional text to match pattern 'prefix_filter: close'")
        print("                 (e.g., 'prove core', 'Verify shard proof')")
        sys.exit(1)

    filename = sys.argv[1]
    prefix_filter = sys.argv[2] if len(sys.argv) > 2 else None

    if prefix_filter:
        print(f"Filtering for lines matching pattern '{prefix_filter}: close'...\n")

    sums = []

    try:
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                result = parse_log_line(line, prefix_filter)
                if result:
                    busy_ms, idle_ms = result
                    total_ms = busy_ms + idle_ms
                    sums.append(total_ms)
                    print(f"Line {line_num}: busy={busy_ms:.6f}ms, idle={idle_ms:.6f}ms, sum={total_ms:.6f}ms")
        
        if not sums:
            print("\nNo valid log entries found.")
            return
        
        stats = calculate_statistics(sums)
        
        print("\n" + "="*50)
        print("STATISTICS FOR time.busy + time.idle (in ms)")
        print("="*50)
        print(f"Total entries: {len(sums)}")
        print(f"Mean:          {stats['mean']:.6f} ms")
        print(f"Median:        {stats['median']:.6f} ms")
        print(f"Std Dev:       {stats['stddev']:.6f} ms")
        print(f"Min:           {stats['min']:.6f} ms")
        print(f"Max:           {stats['max']:.6f} ms")
        print(f"Range:         {stats['range']:.6f} ms")
        
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()