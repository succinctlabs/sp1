#!/usr/bin/env python3
"""Compare two criterion baselines with adaptive precision and Welch's t-test.

Reads directly from criterion's target/criterion/ directories (sample.json +
estimates.json). One or more baseline names per side may be supplied — when
more than one is given, their per-batch samples are pooled, which is how
--repeat N rounds get combined into one comparison.

Output columns:
  group     bench name (relative path under target/criterion/)
  <a>       mean ± stderr from pooled samples (side A, in adaptive units)
  <b>       same, side B
  delta     (mean_a - mean_b) / mean_b * 100  — positive = side A slower
  95% CI    Welch's t-test confidence interval on the percentage change
  t         t-statistic; |t| > ~2 corresponds to p < 0.05 for moderate df

The CI captures within-run noise only — it cannot detect cross-run bias
(thermal drift, scheduler luck, etc.). For that, use --repeat N≥2 in the
driver script and look at the spread.
"""

import argparse
import json
import math
import sys
from pathlib import Path


# t-critical values for 95% CI (two-sided), keyed by floor of degrees of
# freedom. For df above the largest key, fall back to 1.96 (normal limit).
T_CRITICAL_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    12: 2.179, 15: 2.131, 20: 2.086, 30: 2.042, 60: 2.000, 120: 1.980,
}


def t_critical(df: float) -> float:
    df = max(1, int(df))
    keys = sorted(T_CRITICAL_95)
    for k in keys:
        if df <= k:
            return T_CRITICAL_95[k]
    return 1.96


def pick_unit(point_ns: float):
    if point_ns >= 1e9:
        return "s", 1e-9
    if point_ns >= 1e6:
        return "ms", 1e-6
    if point_ns >= 1e3:
        return "us", 1e-3
    return "ns", 1.0


def fmt_meas(point_ns: float, err_ns: float) -> str:
    unit, scale = pick_unit(point_ns)
    p, e = point_ns * scale, err_ns * scale
    if e > 0:
        d = max(0, min(6, int(-math.floor(math.log10(e)))))
    else:
        d = 4
    return f"{p:.{d}f}±{e:.{d}f}{unit}"


def read_batch_means(criterion_dir: Path, bench: str, baseline: str):
    """Return per-batch mean times (ns/iter) for one (bench, baseline) pair,
    or None if the data is missing."""
    sample_path = criterion_dir / bench / baseline / "sample.json"
    if not sample_path.is_file():
        return None
    sample = json.loads(sample_path.read_text())
    iters = sample.get("iters", [])
    times = sample.get("times", [])
    return [t / i for t, i in zip(times, iters) if i > 0]


def list_benches(criterion_dir: Path, baselines: list) -> set:
    """Set of bench paths (relative to criterion_dir) that have sample.json
    for every baseline in `baselines`."""
    if not criterion_dir.exists():
        return set()
    candidates = set()
    for sample_path in criterion_dir.rglob("sample.json"):
        baseline_dir = sample_path.parent
        if baseline_dir.name in baselines:
            bench_path = baseline_dir.parent.relative_to(criterion_dir).as_posix()
            candidates.add(bench_path)
    return {
        b for b in candidates
        if all((criterion_dir / b / bn / "sample.json").is_file() for bn in baselines)
    }


def stats(samples):
    n = len(samples)
    if n < 2:
        return None
    mean = sum(samples) / n
    var = sum((x - mean) ** 2 for x in samples) / (n - 1)
    return n, mean, var


def welch_change(samples_a, samples_b):
    """Welch's t-test on the difference in means, reported as a percentage
    of mean_b. Returns (pct, ci_lo, ci_hi, t_stat, df) or None."""
    sa = stats(samples_a)
    sb = stats(samples_b)
    if not sa or not sb:
        return None
    n_a, m_a, var_a = sa
    n_b, m_b, var_b = sb
    if m_b == 0:
        return None
    se = math.sqrt(var_a / n_a + var_b / n_b)
    if se == 0:
        return None
    diff = m_a - m_b
    t_stat = diff / se
    # Welch–Satterthwaite degrees of freedom.
    num = (var_a / n_a + var_b / n_b) ** 2
    den = ((var_a / n_a) ** 2 / (n_a - 1)) + ((var_b / n_b) ** 2 / (n_b - 1))
    df = num / den if den > 0 else float("inf")
    tc = t_critical(df)
    pct = diff / m_b * 100
    ci_lo = (diff - tc * se) / m_b * 100
    ci_hi = (diff + tc * se) / m_b * 100
    return pct, ci_lo, ci_hi, t_stat, df


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--target-a", required=True, type=Path,
                    help="path to side A's target/criterion directory")
    ap.add_argument("--baselines-a", required=True,
                    help="comma-separated baseline names for side A")
    ap.add_argument("--label-a", required=True,
                    help="column header for side A")
    ap.add_argument("--target-b", required=True, type=Path)
    ap.add_argument("--baselines-b", required=True)
    ap.add_argument("--label-b", required=True)
    args = ap.parse_args()

    baselines_a = [b for b in args.baselines_a.split(",") if b]
    baselines_b = [b for b in args.baselines_b.split(",") if b]

    benches_a = list_benches(args.target_a, baselines_a)
    benches_b = list_benches(args.target_b, baselines_b)
    common = sorted(benches_a & benches_b)
    only_a = sorted(benches_a - benches_b)
    only_b = sorted(benches_b - benches_a)

    rows = []
    for bench in common:
        pooled_a = []
        for bn in baselines_a:
            data = read_batch_means(args.target_a, bench, bn)
            if data:
                pooled_a.extend(data)
        pooled_b = []
        for bn in baselines_b:
            data = read_batch_means(args.target_b, bench, bn)
            if data:
                pooled_b.extend(data)

        sa = stats(pooled_a)
        sb = stats(pooled_b)
        if not sa or not sb:
            continue
        n_a, m_a, var_a = sa
        n_b, m_b, var_b = sb
        cell_a = fmt_meas(m_a, math.sqrt(var_a / n_a))
        cell_b = fmt_meas(m_b, math.sqrt(var_b / n_b))

        result = welch_change(pooled_a, pooled_b)
        if result:
            pct, lo, hi, t, df = result
            change_str = f"{pct:+.2f}%"
            ci_str = f"[{lo:+.2f}, {hi:+.2f}]%"
            t_str = f"{t:+.1f}"
        else:
            change_str = ci_str = t_str = ""
        rows.append((bench, cell_a, cell_b, change_str, ci_str, t_str))

    headers = ("group", args.label_a, args.label_b, "delta", "95% CI", "t")
    widths = [
        max(len(headers[i]), max((len(r[i]) for r in rows), default=0))
        for i in range(len(headers))
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for r in rows:
        print(fmt.format(*r))

    print()
    print("delta = (a - b) / b * 100  (positive = side A slower)")
    print("95% CI is Welch's t-test on per-batch means (within-run noise only;")
    print("does not capture cross-run bias like thermal drift or scheduler luck).")
    print("|t| > ~2 corresponds to p < 0.05 for moderate sample counts.")
    if len(baselines_a) > 1 or len(baselines_b) > 1:
        print(f"Pooled across {max(len(baselines_a), len(baselines_b))} round(s) per side.")
    if only_a:
        print(f"Only in {args.label_a}: {', '.join(only_a)}")
    if only_b:
        print(f"Only in {args.label_b}: {', '.join(only_b)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
