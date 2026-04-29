#!/usr/bin/env python3
"""Compare two benchmark runs from leaderboard.ndjson.

Usage:
    bench/compare.py <baseline_sha> <candidate_sha>
    bench/compare.py baseline-2025-01-01 HEAD

Reads bench/leaderboard.ndjson and prints a delta table for every workload
that has entries for both SHAs. Uses a Wilcoxon rank-sum test on the raw
replicates when available.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

def load_leaderboard(path: Path) -> list[dict]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries

def find_entries(entries: list[dict], sha_prefix: str) -> list[dict]:
    """Find entries matching a SHA prefix or notes containing the string."""
    matches = [e for e in entries if e["sha"].startswith(sha_prefix)]
    if not matches:
        # Try matching in notes (for baseline-<date> tags)
        matches = [e for e in entries if sha_prefix in e.get("notes", "")]
    return matches

def rank_sum_p(a: list[float], b: list[float]) -> float | None:
    """Simple Mann-Whitney U / Wilcoxon rank-sum p-value (two-sided).

    Returns None if samples are too small.
    """
    if len(a) < 2 or len(b) < 2:
        return None
    try:
        from scipy.stats import mannwhitneyu
        _, p = mannwhitneyu(a, b, alternative="two-sided")
        return p
    except ImportError:
        # Fallback: no scipy, skip p-value
        return None

def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    baseline_id, candidate_id = sys.argv[1], sys.argv[2]
    leaderboard_path = Path(__file__).parent / "leaderboard.ndjson"

    if not leaderboard_path.exists():
        print(f"Leaderboard not found: {leaderboard_path}", file=sys.stderr)
        sys.exit(1)

    entries = load_leaderboard(leaderboard_path)
    baseline_entries = find_entries(entries, baseline_id)
    candidate_entries = find_entries(entries, candidate_id)

    if not baseline_entries:
        print(f"No entries found for baseline '{baseline_id}'", file=sys.stderr)
        sys.exit(1)
    if not candidate_entries:
        print(f"No entries found for candidate '{candidate_id}'", file=sys.stderr)
        sys.exit(1)

    # Group by workload — take the latest entry per workload for each SHA
    def latest_by_workload(elist: list[dict]) -> dict[str, dict]:
        by_w: dict[str, dict] = {}
        for e in elist:
            w = e["workload"]
            by_w[w] = e  # last entry wins (append-only log)
        return by_w

    base_by_w = latest_by_workload(baseline_entries)
    cand_by_w = latest_by_workload(candidate_entries)

    common_workloads = sorted(set(base_by_w) & set(cand_by_w))
    if not common_workloads:
        print("No common workloads between baseline and candidate.", file=sys.stderr)
        sys.exit(1)

    print(f"Baseline:  {baseline_id} ({baseline_entries[0]['sha']})")
    print(f"Candidate: {candidate_id} ({candidate_entries[0]['sha']})")
    print()
    print(f"{'Workload':<15} {'Baseline (ms)':>14} {'Candidate (ms)':>14} {'Delta':>10} {'p-value':>10}")
    print("-" * 67)

    for w in common_workloads:
        b = base_by_w[w]
        c = cand_by_w[w]
        b_ms = b["prove_ms_median"]
        c_ms = c["prove_ms_median"]
        delta_pct = (c_ms - b_ms) / b_ms * 100

        # Try rank-sum on raw replicates
        b_raw = b.get("all_prove_ms", [])
        c_raw = c.get("all_prove_ms", [])
        p = rank_sum_p(b_raw, c_raw)

        p_str = f"{p:.4f}" if p is not None else "n/a"
        sign = "+" if delta_pct > 0 else ""
        print(f"{w:<15} {b_ms:>14.1f} {c_ms:>14.1f} {sign}{delta_pct:>8.1f}% {p_str:>10}")

    print()

if __name__ == "__main__":
    main()
