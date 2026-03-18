#!/usr/bin/env python3
"""Plot Figure 3 p99 latency against configured eBPF instructions."""

import argparse
import os

import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import pandas as pd

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

DEFAULT_RESULTS_CSV = "figure3_results.csv"
DEFAULT_MOTIVATING_OUTPUT = "figure3_p99_motivating.png"
DEFAULT_EVALUATION_OUTPUT = "figure3_p99_evaluation.png"


def detect_x_col(df):
    for col in ("configured_insn_count", "work_iters", "die_after"):
        if col in df.columns:
            return col
    raise ValueError(
        "CSV must include configured_insn_count, work_iters, or die_after"
    )


def work_iters_to_insn_count(work_iters):
    return 17 + 26 * (work_iters // 128)


def work_iters_to_insn_count_continuous(work_iters):
    return 17 + 26 * (work_iters / 128.0)


def derive_companion_csv_path(base_path, suffix):
    stem, ext = os.path.splitext(base_path)
    if ext:
        return f"{stem}-{suffix}{ext}"
    return f"{base_path}-{suffix}"


def load_results(csv_path, default_mode=None):
    df = pd.read_csv(csv_path, comment="#")

    if "exp_mode" not in df.columns:
        df["exp_mode"] = default_mode if default_mode else "unknown"

    for col in (
        "configured_insn_count",
        "work_iters",
        "die_after",
        "p99_latency_ms",
        "avg_bpf_runtime_ns",
        "termination_hits",
        "avg_elapsed_ns_before_termination",
        "avg_completed_work_iters_before_termination",
        "time_limit_ns",
        "time_limit_us",
    ):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if "p99_latency_ms" not in df.columns:
        raise ValueError(f"{csv_path} is missing p99_latency_ms")
    if "avg_bpf_runtime_ns" not in df.columns:
        df["avg_bpf_runtime_ns"] = 0.0
    if "termination_hits" not in df.columns:
        df["termination_hits"] = 0.0
    if "avg_elapsed_ns_before_termination" not in df.columns:
        df["avg_elapsed_ns_before_termination"] = 0.0
    if "avg_completed_work_iters_before_termination" not in df.columns:
        df["avg_completed_work_iters_before_termination"] = 0.0

    if "configured_insn_count" not in df.columns:
        x_col = detect_x_col(df)
        if x_col == "configured_insn_count":
            df["configured_insn_count"] = df[x_col]
        else:
            df["configured_insn_count"] = df[x_col].fillna(0).astype(int).apply(
                work_iters_to_insn_count
            )

    df["configured_insn_count"] = df["configured_insn_count"].fillna(0)
    if "time_limit_ns" not in df.columns:
        df["time_limit_ns"] = 0
    if "time_limit_us" not in df.columns:
        df["time_limit_us"] = df["time_limit_ns"] / 1000.0

    agg = {
        "p99_latency_ms": ["mean", "std"],
        "avg_bpf_runtime_ns": "mean",
        "termination_hits": "mean",
        "avg_elapsed_ns_before_termination": "mean",
        "avg_completed_work_iters_before_termination": "mean",
        "time_limit_ns": "first",
        "time_limit_us": "first",
        "exp_mode": "first",
    }
    grouped = (
        df.sort_values("configured_insn_count")
        .groupby("configured_insn_count", sort=True)
        .agg(agg)
        .reset_index()
    )
    grouped.columns = [
        f"{left}_{right}" if right and right != "first" else left
        for left, right in grouped.columns
    ]
    grouped = grouped.rename(
        columns={
            "p99_latency_ms_mean": "p99_latency_ms",
            "avg_bpf_runtime_ns_mean": "avg_bpf_runtime_ns",
            "termination_hits_mean": "termination_hits",
            "avg_elapsed_ns_before_termination_mean": "avg_elapsed_ns_before_termination",
            "avg_completed_work_iters_before_termination_mean": "avg_completed_work_iters_before_termination",
        }
    )
    grouped["p99_latency_ms_std"] = grouped["p99_latency_ms_std"].fillna(0)
    return grouped


def style_axes(ax):
    ax.set_xlabel("Configured eBPF instructions", fontsize=8)
    ax.set_ylabel("p99 latency (ms)", fontsize=8)
    ax.grid(True, linewidth=0.3, alpha=0.5)
    ax.tick_params(axis="both", which="major", labelsize=7, pad=1)
    ax.tick_params(axis="both", which="minor", labelsize=6)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=5, integer=True))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(nbins=5))
    ax.spines["top"].set_linewidth(0.5)
    ax.spines["right"].set_linewidth(0.5)
    ax.spines["bottom"].set_linewidth(0.5)
    ax.spines["left"].set_linewidth(0.5)


def save_plot(fig, output_path):
    pdf_path = output_path.rsplit(".", 1)[0] + ".pdf"
    fig.savefig(output_path, bbox_inches="tight", dpi=300)
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {output_path}, {pdf_path}")


def plot_motivating(csv_path, output_path):
    df = load_results(csv_path, default_mode="no_termination")
    fig, ax = plt.subplots(1, 1, figsize=(3.2, 2.2), dpi=300, constrained_layout=True)

    ax.errorbar(
        df["configured_insn_count"],
        df["p99_latency_ms"],
        yerr=df["p99_latency_ms_std"],
        marker="o",
        linewidth=1.1,
        markersize=2.8,
        capsize=2,
        capthick=0.6,
        elinewidth=0.6,
        color="#2563eb",
    )
    ax.set_title("p99 latency vs configured eBPF instructions", fontsize=8, pad=2)
    style_axes(ax)
    save_plot(fig, output_path)


def estimate_measured_cutoff(df_budget):
    if "termination_hits" not in df_budget.columns:
        return None

    hit_points = df_budget[df_budget["termination_hits"] > 0].copy()
    if hit_points.empty:
        return None

    weights = hit_points["termination_hits"].clip(lower=0)
    if (
        "avg_completed_work_iters_before_termination" in hit_points.columns
        and (hit_points["avg_completed_work_iters_before_termination"] > 0).any()
        and weights.sum() > 0
    ):
        estimates = work_iters_to_insn_count_continuous(
            hit_points["avg_completed_work_iters_before_termination"]
        )
        return float((estimates * weights).sum() / weights.sum())

    return float(hit_points["configured_insn_count"].iloc[0])


def plot_evaluation(no_term_csv, budget_csv, output_path):
    df_no = load_results(no_term_csv, default_mode="no_termination")
    df_budget = load_results(budget_csv, default_mode="termination_budgeted")

    fig, ax = plt.subplots(1, 1, figsize=(3.5, 2.5), dpi=300, constrained_layout=True)
    ax.errorbar(
        df_no["configured_insn_count"],
        df_no["p99_latency_ms"],
        yerr=df_no["p99_latency_ms_std"],
        marker="o",
        linewidth=1.1,
        markersize=2.8,
        capsize=2,
        capthick=0.6,
        elinewidth=0.6,
        color="#2563eb",
        label="No termination",
    )
    ax.errorbar(
        df_budget["configured_insn_count"],
        df_budget["p99_latency_ms"],
        yerr=df_budget["p99_latency_ms_std"],
        marker="s",
        linewidth=1.1,
        markersize=2.8,
        capsize=2,
        capthick=0.6,
        elinewidth=0.6,
        color="#dc2626",
        label="Budgeted termination",
    )

    budget_us = float(df_budget["time_limit_us"].iloc[0]) if not df_budget.empty else 0.0
    cutoff_x = estimate_measured_cutoff(df_budget)
    if cutoff_x is None:
        print("Warning: budgeted CSV recorded no termination hits")
    else:
        ax.axvline(
            cutoff_x,
            color="#059669",
            linestyle="--",
            linewidth=1.0,
            alpha=0.9,
            label=f"Measured {budget_us:.1f} us cutoff",
        )
        print(f"Measured budget cutoff at {cutoff_x:.0f} configured instructions")

    ax.set_title("Per-invocation budgeted termination", fontsize=8, pad=2)
    style_axes(ax)
    ax.legend(
        fontsize=6,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=2,
        frameon=True,
        framealpha=0.9,
        edgecolor="0.8",
        handlelength=1.2,
        columnspacing=0.8,
        handletextpad=0.4,
        labelspacing=0.3,
    )
    save_plot(fig, output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Plot Figure 3 p99 latency against configured eBPF instructions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--figure",
        choices=("motivating", "evaluation"),
        required=True,
        help="which Figure 3 view to render",
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_RESULTS_CSV,
        help="single no-termination CSV for the motivating plot",
    )
    parser.add_argument(
        "--no-term-csv",
        default=DEFAULT_RESULTS_CSV,
        help="no-termination CSV for the evaluation plot",
    )
    parser.add_argument(
        "--budget-csv",
        help="budgeted-termination CSV for the evaluation plot; defaults to <no-term-csv>-budget",
    )
    parser.add_argument("--output", help="output PNG path")
    args = parser.parse_args()

    if args.figure == "motivating":
        output_path = args.output if args.output else DEFAULT_MOTIVATING_OUTPUT
        csv_path = args.csv
        plot_motivating(csv_path, output_path)
        return

    output_path = args.output if args.output else DEFAULT_EVALUATION_OUTPUT
    budget_csv = args.budget_csv or derive_companion_csv_path(args.no_term_csv, "budget")
    plot_evaluation(args.no_term_csv, budget_csv, output_path)


if __name__ == "__main__":
    main()
