#!/usr/bin/env python3
"""
Plot the additive figure-8 worst-case verifier benchmark as a 3x2 grid.
"""

import argparse
import sys
from pathlib import Path

try:
    import matplotlib as mpl
    import matplotlib.pyplot as plt
    import pandas as pd
except ModuleNotFoundError as exc:
    missing = exc.name or "required plotting dependency"

    print(
        f"Missing Python dependency: {missing}. "
        "Install the plotting requirements (for example: pip install matplotlib pandas).",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42


SHAPE_LAYOUT = [
    ("rt_fanin", "Verification time", "Potential live object slots", "Many states, one unwind site"),
    ("rt_ladder", "Verification time", "Global call depth", "Deep unwind call chain"),
    ("rt_many_pcs", "Verification time", "Distinct unwind sites", "Many unwind sites in one subprog"),
    ("mem_big_single_desc", "Memory overhead", "Live stack bytes at unwind site", "One large unwind frame"),
    ("mem_deep_ladder", "Memory overhead", "Global call depth", "Repeated unwind frames on call chain"),
    ("mem_many_big_descs", "Memory overhead", "Distinct unwind sites", "Many large unwind frames"),
]

STYLES = {
    "saterm": {"label": "saterm", "color": "#1d4ed8", "marker": "o"},
    "kflex": {"label": "kflex", "color": "#dc2626", "marker": "s"},
}


def same_file(path_a: Path, path_b: Path) -> bool:
    try:
        return path_a.samefile(path_b)
    except FileNotFoundError:
        return False


def mem_deep_ladder_flat(df: pd.DataFrame) -> bool:
    ladder = df[(df["kernel_type"] == "kflex") & (df["shape"] == "mem_deep_ladder")]
    if ladder.empty:
        return False

    grouped = ladder.groupby("param_value")["unwind_bytes"].mean().sort_index()
    if len(grouped.index) < 2:
        return False
    return grouped.nunique() == 1


def validate_kflex_input(csv_path: Path, df: pd.DataFrame) -> None:
    if not mem_deep_ladder_flat(df):
        return

    msg = [
        f"{csv_path} looks stale: kflex mem_deep_ladder unwind_bytes are flat across call depths.",
        "Re-run `sudo ./figure8_worstcase.user kflex` so the canonical plot input is refreshed.",
    ]

    alternate = csv_path.with_name("worstcase.csv")
    if alternate.exists() and not same_file(csv_path, alternate):
        alt_df = pd.read_csv(alternate)
        if not mem_deep_ladder_flat(alt_df):
            msg.append(f"A non-flat convenience copy is present at {alternate}; the canonical kflex CSV needs to be resynced.")

    raise SystemExit(" ".join(msg))


def unit_scale(max_value: float, memory: bool) -> tuple[float, str]:
    if memory:
        if max_value >= 1024 * 1024:
            return 1024 * 1024.0, "MiB"
        if max_value >= 1024:
            return 1024.0, "KiB"
        return 1.0, "B"

    if max_value >= 1_000_000_000:
        return 1_000_000_000.0, "s"
    if max_value >= 1_000_000:
        return 1_000_000.0, "ms"
    if max_value >= 1_000:
        return 1_000.0, "us"
    return 1.0, "ns"


def aggregate(df: pd.DataFrame, value_col: str) -> pd.DataFrame:
    grouped = (
        df.groupby(["kernel_type", "param_value"])[value_col]
        .agg(["mean", "std"])
        .reset_index()
        .rename(columns={"mean": "mean_value", "std": "std_value"})
    )
    grouped["std_value"] = grouped["std_value"].fillna(0.0)
    return grouped


def plot_series(ax: plt.Axes, grouped: pd.DataFrame, ylabel: str, title: str, xlabel: str) -> None:
    max_value = (grouped["mean_value"] + grouped["std_value"]).max()
    scale, unit = unit_scale(max_value, ylabel == "Memory overhead")

    for kernel, style in STYLES.items():
        kdf = grouped[grouped["kernel_type"] == kernel].sort_values("param_value")
        if kdf.empty:
            continue

        x = kdf["param_value"]
        y = kdf["mean_value"] / scale
        yerr = kdf["std_value"] / scale

        ax.plot(
            x,
            y,
            marker=style["marker"],
            linewidth=1.0,
            markersize=2.6,
            color=style["color"],
            label=style["label"],
        )
        ax.fill_between(x, y - yerr, y + yerr, color=style["color"], alpha=0.15, linewidth=0)

    y_axis = "Verifier load time" if ylabel == "Verification time" else "Unwind metadata size"
    ax.set_xlabel(xlabel, fontsize=7)
    ax.set_ylabel(f"{y_axis} ({unit})", fontsize=7)
    ax.set_title(title, fontsize=7, pad=2)
    ax.set_ylim(bottom=0)
    ax.tick_params(axis="both", which="major", labelsize=6, pad=1)
    ax.ticklabel_format(axis="x", style="plain", useOffset=False)
    ax.grid(True, linewidth=0.25, alpha=0.45)


def plot_worstcase(saterm_csv: Path, kflex_csv: Path, output_base: str) -> None:
    parts = []
    for csv_path in (saterm_csv, kflex_csv):
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            if csv_path == kflex_csv:
                validate_kflex_input(csv_path, df)
            parts.append(df)
        else:
            print(f"Warning: {csv_path} not found, skipping.", file=sys.stderr)
    if not parts:
        raise SystemExit("No CSV files found; nothing to plot.")
    df = pd.concat(parts, ignore_index=True)

    fig, axes = plt.subplots(2, 3, figsize=(8.0, 4.5), dpi=300, constrained_layout=True)
    fig.get_layout_engine().set(rect=(0, 0, 1, 0.93))

    for ax, (shape, metric_kind, xlabel, title) in zip(axes.flat, SHAPE_LAYOUT):
        sdf = df[df["shape"] == shape]
        if sdf.empty:
            raise ValueError(f"Missing rows for shape '{shape}'")

        value_col = "verification_time_ns" if metric_kind == "Verification time" else "unwind_bytes"
        grouped = aggregate(sdf, value_col)
        plot_series(ax, grouped, metric_kind, title, xlabel)

    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False, fontsize=7)

    png_path = f"{output_base}.png"
    pdf_path = f"{output_base}.pdf"
    fig.savefig(png_path, bbox_inches="tight", dpi=300)
    fig.savefig(pdf_path, bbox_inches="tight")
    print(f"Saved: {png_path}, {pdf_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot the figure-8 worst-case verifier benchmark")
    parser.add_argument("--saterm", default="saterm_worstcase.csv")
    parser.add_argument("--kflex", default="kflex_worstcase.csv")
    parser.add_argument("--output", default="figure8_worstcase")
    args = parser.parse_args()

    plot_worstcase(Path(args.saterm), Path(args.kflex), args.output)


if __name__ == "__main__":
    main()
