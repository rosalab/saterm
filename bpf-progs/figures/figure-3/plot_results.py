#!/usr/bin/env python3
"""
Plot Figure 3: Impact of BPF program termination on Redis throughput
Single plot showing throughput loss only, styled for publication.
"""

import matplotlib.pyplot as plt
import matplotlib as mpl
import pandas as pd
import sys

# Use Type 1 fonts for publication
mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42


def plot_figure3(csv_path='figure3_results.csv', output_path='figure3.png'):
    # Read CSV data (skip comment lines)
    df = pd.read_csv(csv_path, comment='#')

    # Calculate throughput loss percentage
    if 'baseline_ops_sec' in df.columns:
        baseline = df['baseline_ops_sec'].iloc[0]
    else:
        # Fallback: use first measurement as baseline if column doesn't exist
        baseline = df['ops_sec'].iloc[0]

    df['throughput_loss_pct'] = (1 - df['ops_sec'] / baseline) * 100

    # Get the "no termination" value (at die_after=10000)
    no_term_value = df.loc[df['die_after'] == 10000, 'throughput_loss_pct']
    if not no_term_value.empty:
        no_term_loss = no_term_value.iloc[0]
    else:
        # Fallback: use max die_after value if 10000 not found
        max_die_after = df['die_after'].max()
        no_term_loss = df.loc[df['die_after'] == max_die_after, 'throughput_loss_pct'].iloc[0]

    # Figure setup: single plot for column format
    fig, ax = plt.subplots(
        1, 1,
        figsize=(3.0, 2.0),
        dpi=300,
        constrained_layout=True,
    )

    # Styling parameters
    linewidth = 1.0
    markersize = 2.5
    color = '#2563eb'  # blue

    # Plot: Throughput Loss % vs Iterations until termination
    ax.plot(
        df['die_after'],
        df['throughput_loss_pct'],
        marker='o',
        linewidth=linewidth,
        markersize=markersize,
        color=color,
    )

    ax.set_xlabel('Iterations until termination', fontsize=8)
    ax.set_ylabel('App throughput loss (%)', fontsize=8)
    ax.set_title('Redis throughput loss', fontsize=8, pad=1)

    # Add baseline reference line at 0%
    ax.axhline(
        y=0,
        color='#10b981',
        linestyle='--',
        linewidth=1.5,
        alpha=0.9,
        label='Baseline (no loss)'
    )

    # Add no termination line
    ax.axhline(
        y=no_term_loss,
        color='#2563eb',
        linestyle=':',
        linewidth=1.2,
        alpha=0.8,
        label='No termination'
    )

    # Add baseline point at max x-value
    # max_die_after = df['die_after'].max()
    # ax.scatter(
    #     [max_die_after],
    #     [0],
    #     color='#10b981',
    #     s=8,
    #     marker='o',
    #     zorder=5
    # )
    ax.legend(fontsize=7, loc='center right', frameon=False, handlelength=1.5)

    # Apply styling
    ax.tick_params(axis='both', which='major', labelsize=7, pad=1)
    ax.tick_params(axis='both', which='minor', labelsize=6)
    ax.grid(True, linewidth=0.3, alpha=0.5)
    ax.spines['top'].set_linewidth(0.5)
    ax.spines['right'].set_linewidth(0.5)
    ax.spines['bottom'].set_linewidth(0.5)
    ax.spines['left'].set_linewidth(0.5)

    # Force y-axis to start at -0.1 with padding at top
    y_min = -0.1
    y_max = df['throughput_loss_pct'].max()
    padding = (y_max - y_min) * 0.05  # 5% padding
    ax.set_ylim(-1.0, y_max + padding)

    # Save figures
    fig.savefig(output_path, bbox_inches='tight', dpi=300)
    fig.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
    print(f"Saved: {output_path}, {output_path.replace('.png', '.pdf')}")

    # Display summary statistics
    print("\n=== Summary Statistics ===")
    print(f"Baseline throughput: {baseline:.2f} ops/sec")
    print(f"Throughput range: {df['ops_sec'].min():.2f} - {df['ops_sec'].max():.2f} ops/sec")
    print(f"Throughput loss range: {df['throughput_loss_pct'].min():.1f}% - {df['throughput_loss_pct'].max():.1f}%")
    print(f"Max throughput loss: {df['throughput_loss_pct'].max():.1f}% (at die_after={df.loc[df['throughput_loss_pct'].idxmax(), 'die_after']:.0f})")
    if 'avg_latency_ms' in df.columns:
        print(f"Latency range: {df['avg_latency_ms'].min():.2f} - {df['avg_latency_ms'].max():.2f} ms")


if __name__ == '__main__':
    csv_path = sys.argv[1] if len(sys.argv) > 1 else 'figure3_results.csv'
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'figure3.png'
    plot_figure3(csv_path, output_path)
