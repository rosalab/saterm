#!/usr/bin/env python3
"""
Plot Figure 5: Runtime of eBPF programs with different iteration counts
Shows two program types: nested_long (exponential) and terminated (constant), 
styled for publication.
"""

import matplotlib.pyplot as plt
import matplotlib as mpl
import pandas as pd
import sys
import numpy as np

# Use Type 1 fonts for publication
mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42


def plot_figure5(csv_path='results.csv', output_path='figure5.png'):
    # Read CSV data
    df = pd.read_csv(csv_path, comment='#')

    # Calculate average runtime for each program and iteration count
    df_avg = df.groupby(['program_name', 'iteration_count'])['runtime_ns'].mean().reset_index()
    
    # Convert runtime from nanoseconds to microseconds for better readability
    df_avg['runtime_us'] = df_avg['runtime_ns'] / 1000.0

    # Separate data for each program
    nested_long = df_avg[df_avg['program_name'] == 'nested_long'].sort_values('iteration_count')
    terminated = df_avg[df_avg['program_name'] == 'terminated'].sort_values('iteration_count')

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
    colors = {
        'nested_long': '#dc2626',      # red
        'single_linear': '#2563eb',    # blue
        'terminated': '#10b981'        # green
    }
    markers = {
        'nested_long': 'o',
        'single_linear': 's',
        'terminated': '^'
    }

    # Plot each program
    if not nested_long.empty:
        ax.plot(
            nested_long['iteration_count'],
            nested_long['runtime_us'],
            marker=markers['nested_long'],
            linewidth=linewidth,
            markersize=markersize,
            color=colors['nested_long'],
            label='Nested (exponential)'
        )

    if not terminated.empty:
        ax.plot(
            terminated['iteration_count'],
            terminated['runtime_us'],
            marker=markers['terminated'],
            linewidth=linewidth,
            markersize=markersize,
            color=colors['terminated'],
            label='Terminated (constant)'
        )

    ax.set_xlabel('Iteration count', fontsize=8)
    ax.set_ylabel('Average runtime (μs)', fontsize=8)
    ax.set_title('eBPF program runtime', fontsize=8, pad=1)

    # Add legend
    ax.legend(fontsize=7, loc='best', frameon=False, handlelength=1.5)

    # Apply styling
    ax.tick_params(axis='both', which='major', labelsize=7, pad=1)
    ax.tick_params(axis='both', which='minor', labelsize=6)
    ax.grid(True, linewidth=0.3, alpha=0.5)
    ax.spines['top'].set_linewidth(0.5)
    ax.spines['right'].set_linewidth(0.5)
    ax.spines['bottom'].set_linewidth(0.5)
    ax.spines['left'].set_linewidth(0.5)

    # Set y-axis limits
    y_max = df_avg['runtime_us'].max()
    padding = y_max * 0.05  # 5% padding
    ax.set_ylim(-10000, y_max + padding)

    # Save figures
    fig.savefig(output_path, bbox_inches='tight', dpi=300)
    fig.savefig(output_path.replace('.png', '.pdf'), bbox_inches='tight')
    print(f"Saved: {output_path}, {output_path.replace('.png', '.pdf')}")

    # Display summary statistics
    print("\n=== Summary Statistics ===")
    for prog_name in ['nested_long', 'terminated']:
        prog_data = df_avg[df_avg['program_name'] == prog_name]
        if not prog_data.empty:
            print(f"\n{prog_name}:")
            print(f"  Runtime range: {prog_data['runtime_us'].min():.2f} - {prog_data['runtime_us'].max():.2f} μs")
            print(f"  Iteration range: {prog_data['iteration_count'].min()} - {prog_data['iteration_count'].max()}")
            if len(prog_data) > 1:
                # Calculate growth factor (last / first)
                first_runtime = prog_data.iloc[0]['runtime_us']
                last_runtime = prog_data.iloc[-1]['runtime_us']
                growth_factor = last_runtime / first_runtime if first_runtime > 0 else 0
                print(f"  Growth factor: {growth_factor:.2f}x")


if __name__ == '__main__':
    csv_path = sys.argv[1] if len(sys.argv) > 1 else 'results.csv'
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'figure5.png'
    plot_figure5(csv_path, output_path)
