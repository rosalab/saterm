#!/usr/bin/env python3
"""
Plot memory in use vs local object count for figure-6.
Styling matches figure-6/plot_results.py.
"""

import re
import sys
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42


BYTE_RE = re.compile(r"(\d+)\s+bytes")


def parse_bytes(path: Path) -> list[int]:
    values: list[int] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            match = BYTE_RE.search(line)
            if match:
                values.append(int(match.group(1)))
    if not values:
        raise ValueError(f"No byte values parsed from {path}")
    return values


def group_sum(values: list[int], group_size: int) -> list[int]:
    if group_size <= 0:
        raise ValueError("group_size must be positive")
    count = (len(values) // group_size) * group_size
    if count == 0:
        raise ValueError("Not enough samples for grouping")
    grouped: list[int] = []
    for idx in range(0, count, group_size):
        grouped.append(sum(values[idx : idx + group_size]))
    return grouped


def plot_mem_overhead(
    kflex_path: Path,
    saterm_path: Path,
    output_path: Path,
    saterm_group_size: int = 5,
) -> None:
    kflex_bytes = parse_bytes(kflex_path)
    saterm_bytes = parse_bytes(saterm_path)
    saterm_totals = group_sum(saterm_bytes, saterm_group_size)

    x_kflex = list(range(len(kflex_bytes)))
    x_saterm = list(range(len(saterm_totals)))

    fig, ax = plt.subplots(1, 1, figsize=(3.0, 2.0), dpi=300, constrained_layout=True)

    colors = ["#2563eb", "#dc2626", "#10b981", "#f59e0b"]
    ax.plot(
        x_kflex,
        kflex_bytes,
        marker="o",
        linewidth=1.0,
        markersize=2.5,
        color=colors[0],
        label="kflex",
    )
    ax.plot(
        x_saterm,
        saterm_totals,
        marker="o",
        linewidth=1.0,
        markersize=2.5,
        color=colors[1],
        label="saterm",
    )

    ax.set_xlabel("Object count", fontsize=8)
    ax.set_ylabel("Memory in use (bytes)", fontsize=8)
    ax.set_title("eBPF object runtime memory overhead", fontsize=8, pad=1)
    ax.legend(fontsize=7, loc="best", frameon=False, handlelength=1.5)
    ax.tick_params(axis="both", which="major", labelsize=7, pad=1)
    ax.grid(True, linewidth=0.3, alpha=0.5)

    fig.savefig(output_path, bbox_inches="tight", dpi=300)
    fig.savefig(output_path.with_suffix(".pdf"), bbox_inches="tight")
    print(f"Saved: {output_path}, {output_path.with_suffix('.pdf')}")


def main() -> None:
    kflex_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("kflex.md")
    saterm_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("saterm.md")
    output_path = (
        Path(sys.argv[3]) if len(sys.argv) > 3 else Path("figure6_mem_overhead.png")
    )
    plot_mem_overhead(kflex_path, saterm_path, output_path)


if __name__ == "__main__":
    main()
