#!/usr/bin/env python3
"""
Plot Figure 8 and Figure 9:
- Figure 8: Verification time vs number of branches
- Figure 9: Termination time vs number of objects (object tracking)
- Figure 8 (memory): Load-time memory vs number of objects (with optional baseline)
"""

import argparse
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42


def _unit_scale(max_value):
    if max_value >= 1_000_000_000:
        return 1_000_000_000.0, "s"
    if max_value >= 1_000_000:
        return 1_000_000.0, "ms"
    if max_value >= 1_000:
        return 1_000.0, "us"
    return 1.0, "ns"


def _load_pair_csv(saterm_csv, kflex_csv):
    saterm_df = pd.read_csv(saterm_csv)
    kflex_df = pd.read_csv(kflex_csv)
    return pd.concat([saterm_df, kflex_df], ignore_index=True)


def _plot_line_with_std(ax, stats_df, x_col, y_col, y_std_col, styles):
    for kernel, style in styles.items():
        kdf = stats_df[stats_df["kernel_type"] == kernel].sort_values(x_col)
        if kdf.empty:
            continue

        x = kdf[x_col]
        y = kdf[y_col]
        yerr = kdf[y_std_col]

        ax.plot(
            x,
            y,
            marker=style["marker"],
            linewidth=0.9,
            markersize=2.0,
            color=style["color"],
            label=style["label"],
        )
        ax.fill_between(x, y - yerr, y + yerr, color=style["color"], alpha=0.15, linewidth=0)


def plot_branches(branches_saterm_csv, branches_kflex_csv, output_base="figure8_branches"):
    df = _load_pair_csv(branches_saterm_csv, branches_kflex_csv)
    if df.empty:
        raise ValueError("No branch benchmark rows found")

    stats = (
        df.groupby(["kernel_type", "num_branches"])["verification_time_ns"]
        .agg(["mean", "std"])
        .reset_index()
        .rename(columns={"mean": "mean_ns", "std": "std_ns"})
    )
    stats["std_ns"] = stats["std_ns"].fillna(0.0)

    max_ns = (stats["mean_ns"] + stats["std_ns"]).max()
    scale, unit = _unit_scale(max_ns)
    stats["mean_scaled"] = stats["mean_ns"] / scale
    stats["std_scaled"] = stats["std_ns"] / scale

    fig, ax = plt.subplots(1, 1, figsize=(3.3, 1.8), dpi=300, constrained_layout=True)

    styles = {
        "saterm": {"label": "saterm", "color": "#1d4ed8", "marker": "o"},
        "kflex": {"label": "kflex", "color": "#dc2626", "marker": "s"},
    }
    _plot_line_with_std(ax, stats, "num_branches", "mean_scaled", "std_scaled", styles)

    ax.set_xlabel("Number of branches", fontsize=6)
    ax.set_ylabel(f"Verification time ({unit})", fontsize=6)
    ax.set_title("Verification time vs branch count", fontsize=6, pad=2)
    ax.legend(fontsize=5, loc="best", frameon=False, handlelength=1.5)
    ax.ticklabel_format(axis="x", style="plain", useOffset=False)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.tick_params(axis="both", which="major", labelsize=5, pad=1)
    ax.grid(True, linewidth=0.25, alpha=0.5)

    fig.savefig(f"{output_base}.png", bbox_inches="tight", dpi=300)
    fig.savefig(f"{output_base}.pdf", bbox_inches="tight")
    print(f"Saved: {output_base}.png, {output_base}.pdf")


def plot_objects(objects_saterm_csv, objects_kflex_csv, output_base="figure9"):
    df = _load_pair_csv(objects_saterm_csv, objects_kflex_csv)
    if df.empty:
        raise ValueError("No object benchmark rows found")

    stats = (
        df.groupby(["kernel_type", "num_objects"])["termination_time_ns"]
        .agg(["mean", "std"])
        .reset_index()
        .rename(columns={"mean": "mean_ns", "std": "std_ns"})
    )
    stats["std_ns"] = stats["std_ns"].fillna(0.0)

    max_ns = (stats["mean_ns"] + stats["std_ns"]).max()
    scale, unit = _unit_scale(max_ns)
    stats["mean_scaled"] = stats["mean_ns"] / scale
    stats["std_scaled"] = stats["std_ns"] / scale

    fig, ax = plt.subplots(1, 1, figsize=(3.3, 1.8), dpi=300, constrained_layout=True)

    styles = {
        "saterm": {"label": "saterm", "color": "#1d4ed8", "marker": "o"},
        "kflex": {"label": "kflex", "color": "#dc2626", "marker": "s"},
    }
    _plot_line_with_std(ax, stats, "num_objects", "mean_scaled", "std_scaled", styles)

    ax.set_xlabel("Number of objects", fontsize=6)
    ax.set_ylabel(f"Termination time ({unit})", fontsize=6)
    ax.set_title("Termination time vs object count", fontsize=6, pad=2)
    ax.legend(fontsize=5, loc="best", frameon=False, handlelength=1.5)
    ax.ticklabel_format(axis="x", style="plain", useOffset=False)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.tick_params(axis="both", which="major", labelsize=5, pad=1)
    ax.grid(True, linewidth=0.25, alpha=0.5)

    fig.savefig(f"{output_base}.png", bbox_inches="tight", dpi=300)
    fig.savefig(f"{output_base}.pdf", bbox_inches="tight")
    print(f"Saved: {output_base}.png, {output_base}.pdf")


def plot_memory(
    memory_saterm_csv,
    memory_kflex_csv,
    memory_baseline_csv=None,
    output_base="figure8_memory",
):
    """Plot load-time memory (MemAvailable delta) vs object count.

    baseline_memory_csv is optional; when provided, includes baseline
    (unmodified kernel) as a manual-tag series.
    """
    dfs = []
    for path in [memory_saterm_csv, memory_kflex_csv]:
        if Path(path).exists():
            dfs.append(pd.read_csv(path))
    if memory_baseline_csv and Path(memory_baseline_csv).exists():
        dfs.append(pd.read_csv(memory_baseline_csv))

    if not dfs:
        print("Skipping memory plot: no memory CSV files found")
        return

    df = pd.concat(dfs, ignore_index=True)
    df["mem_delta_kb"] = df["mem_avail_before_kb"] - df["mem_avail_after_kb"]

    stats = (
        df.groupby(["kernel_type", "num_objects"])["mem_delta_kb"]
        .agg(["mean", "std"])
        .reset_index()
        .rename(columns={"mean": "mean_kb", "std": "std_kb"})
    )
    stats["std_kb"] = stats["std_kb"].fillna(0.0)

    fig, ax = plt.subplots(1, 1, figsize=(3.3, 1.8), dpi=300, constrained_layout=True)

    styles = {
        "saterm": {"label": "saterm", "color": "#1d4ed8", "marker": "o"},
        "kflex": {"label": "kflex", "color": "#dc2626", "marker": "s"},
        "baseline": {"label": "baseline (unmodified)", "color": "#6b7280", "marker": "^"},
    }

    for kernel, style in styles.items():
        kdf = stats[stats["kernel_type"] == kernel].sort_values("num_objects")
        if kdf.empty:
            continue

        x = kdf["num_objects"]
        y = kdf["mean_kb"]
        yerr = kdf["std_kb"]

        ax.plot(
            x,
            y,
            marker=style["marker"],
            linewidth=0.9,
            markersize=2.0,
            color=style["color"],
            label=style["label"],
        )
        ax.fill_between(x, y - yerr, y + yerr, color=style["color"], alpha=0.15, linewidth=0)

    ax.set_xlabel("Number of objects", fontsize=6)
    ax.set_ylabel("Load-time memory (KB)", fontsize=6)
    ax.set_title("Load-time memory vs object count", fontsize=6, pad=2)
    ax.legend(fontsize=5, loc="best", frameon=False, handlelength=1.5)
    ax.ticklabel_format(axis="x", style="plain", useOffset=False)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.tick_params(axis="both", which="major", labelsize=5, pad=1)
    ax.grid(True, linewidth=0.25, alpha=0.5)

    fig.savefig(f"{output_base}.png", bbox_inches="tight", dpi=300)
    fig.savefig(f"{output_base}.pdf", bbox_inches="tight")
    print(f"Saved: {output_base}.png, {output_base}.pdf")


def main():
    parser = argparse.ArgumentParser(description="Generate Figure-8 plots")
    parser.add_argument("--branches-saterm", default="saterm_branches.csv")
    parser.add_argument("--branches-kflex", default="kflex_branches.csv")
    parser.add_argument("--objects-saterm", default="saterm_objects.csv")
    parser.add_argument("--objects-kflex", default="kflex_objects.csv")
    parser.add_argument("--memory-saterm", default="saterm_memory.csv")
    parser.add_argument("--memory-kflex", default="kflex_memory.csv")
    parser.add_argument(
        "--memory-baseline",
        default="baseline_memory.csv",
        help="Baseline memory from unmodified kernel (manual tag)",
    )
    parser.add_argument("--branches-output-base", default="figure8_branches")
    parser.add_argument("--objects-output-base", default="figure9",
                        help="Figure 9: termination time vs object count")
    parser.add_argument("--memory-output-base", default="figure8_memory")
    args = parser.parse_args()

    plot_branches(args.branches_saterm, args.branches_kflex, args.branches_output_base)
    plot_objects(args.objects_saterm, args.objects_kflex, args.objects_output_base)
    plot_memory(
        args.memory_saterm,
        args.memory_kflex,
        args.memory_baseline,
        args.memory_output_base,
    )


if __name__ == "__main__":
    main()
