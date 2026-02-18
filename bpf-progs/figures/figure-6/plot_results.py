#!/usr/bin/env python3
"""
Plot Figure 6: Runtime memory overhead for eBPF object allocations.
"""

import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl

mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42


def plot_figure6(csv_path='results.csv', output_path='figure6.png'):
    df = pd.read_csv(csv_path)
    df['mem_delta_kb'] = df['mem_avail_before_kb'] - df['mem_avail_after_alloc_kb']

    grouped = (
        df.groupby(['kernel_type', 'num_objects'])['mem_delta_kb']
        .mean()
        .reset_index()
    )

    fig, ax = plt.subplots(1, 1, figsize=(3.0, 2.0), dpi=300, constrained_layout=True)

    colors = ['#2563eb', '#dc2626', '#10b981', '#f59e0b']
    for idx, (kernel, kdf) in enumerate(grouped.groupby('kernel_type')):
        kdf = kdf.sort_values('num_objects')
        ax.plot(
            kdf['num_objects'],
            kdf['mem_delta_kb'],
            marker='o',
            linewidth=1.0,
            markersize=2.5,
            color=colors[idx % len(colors)],
            label=kernel,
        )

    ax.set_xlabel('Object count', fontsize=8)
    ax.set_ylabel('MemAvailable delta (KB)', fontsize=8)
    ax.set_title('eBPF object runtime memory overhead', fontsize=8, pad=1)
    ax.legend(fontsize=7, loc='best', frameon=False, handlelength=1.5)
    ax.tick_params(axis='both', which='major', labelsize=7, pad=1)
    ax.grid(True, linewidth=0.3, alpha=0.5)

    fig.savefig(output_path, bbox_inches='tight', dpi=300)
    fig.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
    print(f"Saved: {output_path}, {output_path.replace('.png', '.pdf')}")


if __name__ == '__main__':
    csv_path = sys.argv[1] if len(sys.argv) > 1 else 'results.csv'
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'figure6.png'
    plot_figure6(csv_path, output_path)
