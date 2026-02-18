#!/usr/bin/env python3
"""
Plot Figure 7: termination runtime benchmark (paper-style).
"""

import sys

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42


def plot_figure7(csv_path="figure7_results.csv", output_path="figure7.png"):
    df = pd.read_csv(csv_path)
    if df.empty:
        raise ValueError(f"No data rows in {csv_path}")

    stats = (
        df.groupby(["category", "count"])["runtime_ns"]
        .agg(["mean", "std"])
        .reset_index()
        .rename(columns={"mean": "runtime_mean_ns", "std": "runtime_std_ns"})
    )
    stats["runtime_std_ns"] = stats["runtime_std_ns"].fillna(0.0)

    max_runtime_ns = (stats["runtime_mean_ns"] + stats["runtime_std_ns"]).max()
    if max_runtime_ns >= 1_000_000_000:
        runtime_scale = 1_000_000_000.0
        runtime_unit = "s"
    elif max_runtime_ns >= 1_000_000:
        runtime_scale = 1_000_000.0
        runtime_unit = "ms"
    elif max_runtime_ns >= 1_000:
        runtime_scale = 1_000.0
        runtime_unit = "us"
    else:
        runtime_scale = 1.0
        runtime_unit = "ns"

    fig, ax = plt.subplots(1, 1, figsize=(3.3, 1.8), dpi=300, constrained_layout=True)

    styles = {
        "stubbed_helper_expensive": {"label": "Stubbed helper (expensive)", "color": "#1d4ed8", "marker": "v"},
        "unstubbed_helper_expensive": {"label": "Unstubbed helper (expensive)", "color": "#6d28d9", "marker": "X"},
        "real_free": {"label": "Real free", "color": "#dc2626", "marker": "s"},
        "baseline": {"label": "Baseline", "color": "#10b981", "marker": "^"},
        "empty": {"label": "Empty", "color": "#6b7280", "marker": "x"},
        "empty_die": {"label": "Empty + die", "color": "#f59e0b", "marker": "D"},
    }

    for category, style in styles.items():
        cdf = stats[stats["category"] == category].sort_values("count")
        if cdf.empty:
            continue

        x = cdf["count"]
        y = cdf["runtime_mean_ns"] / runtime_scale
        yerr = cdf["runtime_std_ns"] / runtime_scale

        ax.plot(
            x,
            y,
            marker=style["marker"],
            linewidth=0.8,
            markersize=1.8,
            color=style["color"],
            label=style["label"],
        )
        ax.fill_between(x, y - yerr, y + yerr, color=style["color"], alpha=0.15, linewidth=0)

    ax.set_xlabel("Iteration count", fontsize=6)
    ax.set_ylabel(f"Runtime ({runtime_unit})", fontsize=6)
    ax.set_title("Termination runtime benchmark", fontsize=6, pad=2)
    ax.legend(fontsize=5, loc="best", frameon=False, handlelength=1.5)
    ax.ticklabel_format(axis="x", style="plain", useOffset=False)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.tick_params(axis="both", which="major", labelsize=5, pad=1)
    ax.tick_params(axis="both", which="minor", labelsize=4)
    ax.grid(True, linewidth=0.25, alpha=0.5)
    ax.spines["top"].set_linewidth(0.4)
    ax.spines["right"].set_linewidth(0.4)
    ax.spines["bottom"].set_linewidth(0.4)
    ax.spines["left"].set_linewidth(0.4)

    fig.savefig(output_path, bbox_inches="tight", dpi=300)
    fig.savefig(output_path.replace(".png", ".pdf"), bbox_inches="tight")
    print(f"Saved: {output_path}, {output_path.replace('.png', '.pdf')}")


if __name__ == "__main__":
    csv_arg = sys.argv[1] if len(sys.argv) > 1 else "figure7_results.csv"
    out_arg = sys.argv[2] if len(sys.argv) > 2 else "figure7.png"
    plot_figure7(csv_arg, out_arg)
