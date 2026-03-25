#!/usr/bin/env python3
"""Format benchmark_sweep_results.csv into readable prover & verifier overhead tables.

Usage: python3 format_results.py [path/to/benchmark_sweep_results.csv]
       Defaults to ./benchmark_sweep_results.csv if no argument given.
"""

import csv
import os
import sys
from collections import defaultdict


def load_csv(path):
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "total": int(row["num_variables"]),
                "log_stack": int(row["log_num_polynomials"]),
                "stacked": int(row["num_encoding_variables"]),
                "std_p": float(row["std_prover_median_ms"]),
                "std_v": float(row["std_verifier_median_ms"]),
                "zk_p": float(row["zk_prover_median_ms"]),
                "zk_v": float(row["zk_verifier_median_ms"]),
                "p_oh": float(row["prover_overhead"]),
                "v_oh": float(row["verifier_overhead"]),
            })
    return rows


def build_grid(rows, value_key):
    """Build a 2D grid: rows = num_variables, cols = log_num_polynomials."""
    grid = {}
    totals = set()
    stacks = set()
    for r in rows:
        totals.add(r["total"])
        stacks.add(r["log_stack"])
        grid[(r["total"], r["log_stack"])] = r[value_key]
    return grid, sorted(totals), sorted(stacks)


def fmt_val(v, fmt_str):
    if v is None:
        return ""
    return fmt_str.format(v)


def print_table(title, rows, value_key, fmt_str="{:.2f}x"):
    grid, totals, stacks = build_grid(rows, value_key)

    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")
    print()

    # Column header: log_num_polynomials values
    col_w = 9
    header = "total\\log_sh"
    print(f"  {header:>11s}", end="")
    for s in stacks:
        print(f" | {s:^{col_w}}", end="")
    print()

    # Separator
    sep_len = 13 + (col_w + 3) * len(stacks)
    print(f"  {'-' * sep_len}")

    for t in totals:
        print(f"  {t:>11d}", end="")
        for s in stacks:
            val = grid.get((t, s))
            cell = fmt_val(val, fmt_str)
            print(f" | {cell:^{col_w}}", end="")
        print()

    print()


def print_time_table(title, rows, std_key, zk_key):
    """Print a table showing std_time / zk_time (overhead)."""
    grid_std, totals, stacks = build_grid(rows, std_key)
    grid_zk, _, _ = build_grid(rows, zk_key)
    oh_key = "p_oh" if "p" in std_key else "v_oh"
    grid_oh, _, _ = build_grid(rows, oh_key)

    print(f"\n{'=' * 90}")
    print(f"  {title}")
    print(f"{'=' * 90}")
    print()

    col_w = 28
    header = "total\\log_sh"
    print(f"  {header:>11s}", end="")
    for s in stacks:
        print(f" | {s:^{col_w}}", end="")
    print()

    sep_len = 13 + (col_w + 3) * len(stacks)
    print(f"  {'-' * sep_len}")

    for t in totals:
        print(f"  {t:>11d}", end="")
        for s in stacks:
            std_v = grid_std.get((t, s))
            zk_v = grid_zk.get((t, s))
            oh_v = grid_oh.get((t, s))
            if std_v is not None and zk_v is not None:
                cell = f"{std_v:.1f} / {zk_v:.1f} ({oh_v:.2f}x)"
            else:
                cell = ""
            print(f" | {cell:^{col_w}}", end="")
        print()

    print()


def print_summary(rows):
    """Print summary statistics."""
    if not rows:
        return

    p_ohs = [r["p_oh"] for r in rows]
    v_ohs = [r["v_oh"] for r in rows]

    print(f"{'=' * 70}")
    print(f"  SUMMARY  ({len(rows)} parameter combinations)")
    print(f"{'=' * 70}")
    print(f"  Prover overhead:   min={min(p_ohs):.2f}x  max={max(p_ohs):.2f}x  "
          f"avg={sum(p_ohs)/len(p_ohs):.2f}x  median={sorted(p_ohs)[len(p_ohs)//2]:.2f}x")
    print(f"  Verifier overhead: min={min(v_ohs):.2f}x  max={max(v_ohs):.2f}x  "
          f"avg={sum(v_ohs)/len(v_ohs):.2f}x  median={sorted(v_ohs)[len(v_ohs)//2]:.2f}x")
    print()


def main():
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark_sweep_results.csv")
    path = sys.argv[1] if len(sys.argv) > 1 else default_path

    try:
        rows = load_csv(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("No data rows found.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(rows)} data points from {path}")

    # Overhead-only tables (compact)
    print_table("PROVER OVERHEAD (ZK / Standard)", rows, "p_oh")
    print_table("VERIFIER OVERHEAD (ZK / Standard)", rows, "v_oh")

    # Detailed tables: std_ms / zk_ms (overhead)
    print_time_table(
        "PROVER TIMES: std_ms / zk_ms (overhead)",
        rows, "std_p", "zk_p",
    )
    print_time_table(
        "VERIFIER TIMES: std_ms / zk_ms (overhead)",
        rows, "std_v", "zk_v",
    )

    print_summary(rows)


if __name__ == "__main__":
    main()
