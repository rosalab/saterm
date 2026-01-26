#!/usr/bin/env python3
"""
Combined eBPF helper overhead visualization for paper column format.
Three subplots: map iterator, contention, and probe read overhead.
"""
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl

# Use Type 1 fonts for publication
mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42


def main():
    # Load all datasets
    df_map = pd.read_csv("map_iterator_results.csv")
    df_contention = pd.read_csv("contention_results.csv")
    df_probe = pd.read_csv("probe_read_results.csv")

    # Compute helper % for map iterator (helper = map iterator section)
    df_map["helper_pct"] = df_map["avg_map_iter_ns"] / df_map["avg_component_total_ns"] * 100.0

    # Compute helper % for contention (avg and modeled worst-case)
    df_contention["helper_pct_avg"] = (
        df_contention["avg_helper_time_ns"] / df_contention["avg_total_bpf_ns"] * 100.0
    )
    T_base = df_contention["avg_total_bpf_ns"] - df_contention["avg_helper_time_ns"]
    df_contention["helper_pct_max_modeled"] = (
        df_contention["avg_max_wait_ns"] / (T_base + df_contention["avg_max_wait_ns"]) * 100.0
    )

    # Compute helper % for probe read (helper = probe read section)
    df_probe["helper_pct"] = df_probe["avg_probe_ns"] / df_probe["avg_total_bpf_ns"] * 100.0
    df_probe["size_mb"] = df_probe["size_bytes"] / 1e6

    # Convert map elements to thousands
    df_map["n_k"] = df_map["n"] / 1000

    # Figure setup: column width ~3.3", three subplots side by side
    fig, axes = plt.subplots(
        1, 3,
        figsize=(3.3, 1.5),
        dpi=300,
        sharey=True,
        constrained_layout=True,
    )
    fig.get_layout_engine().set(wspace=0.02)

    ax1, ax2, ax3 = axes

    # Common plot styling
    linewidth = 0.8
    markersize = 1.8
    colors = ['#2563eb', '#dc2626']  # blue, red

    # --- Subplot 1: Map Iterator ---
    ax1.plot(
        df_map["n_k"],
        df_map["helper_pct"],
        marker="o",
        linewidth=linewidth,
        markersize=markersize,
        color=colors[0],
    )
    ax1.set_xlabel("map elements (10e3)", fontsize=6)
    ax1.set_ylabel("% of eBPF runtime", fontsize=6)
    ax1.set_title("(a) Iterator", fontsize=6, pad=2)

    # --- Subplot 2: Contention ---
    ax2.plot(
        df_contention["num_threads"],
        df_contention["helper_pct_avg"],
        marker="s",
        linewidth=linewidth,
        markersize=markersize,
        color=colors[0],
        label="avg",
    )
    ax2.plot(
        df_contention["num_threads"],
        df_contention["helper_pct_max_modeled"],
        marker="^",
        linestyle="--",
        linewidth=linewidth,
        markersize=markersize,
        color=colors[1],
        label="worst-case",
    )
    ax2.set_xlabel("threads", fontsize=6)
    ax2.set_title("(b) Contention", fontsize=6, pad=2)
    ax2.legend(fontsize=4.5, loc="upper left", frameon=False, handlelength=1.5)

    # --- Subplot 3: Probe Read ---
    ax3.plot(
        df_probe["size_mb"],
        df_probe["helper_pct"],
        marker="D",
        linewidth=linewidth,
        markersize=markersize,
        color=colors[0],
    )
    ax3.set_xlabel("read size (MB)", fontsize=6)
    ax3.set_title("(c) Argument-dependent", fontsize=6, pad=2)

    # Apply common styling to all axes
    for ax in axes:
        ax.tick_params(axis="both", which="major", labelsize=5, pad=1)
        ax.tick_params(axis="both", which="minor", labelsize=4)
        ax.grid(True, linewidth=0.25, alpha=0.5)
        ax.spines['top'].set_linewidth(0.4)
        ax.spines['right'].set_linewidth(0.4)
        ax.spines['bottom'].set_linewidth(0.4)
        ax.spines['left'].set_linewidth(0.4)

    # Set y-axis limits for consistency
    ax1.set_ylim(0, 100)

    fig.savefig("helper_overhead_combined.png", bbox_inches="tight", dpi=300)
    fig.savefig("helper_overhead_combined.pdf", bbox_inches="tight")
    print("Saved: helper_overhead_combined.png, helper_overhead_combined.pdf")


if __name__ == "__main__":
    main()
