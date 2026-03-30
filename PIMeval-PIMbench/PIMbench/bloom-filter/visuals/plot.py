import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from pathlib import Path

RESULTS = Path(__file__).parent.parent / "PIM" / "results.txt"
OUT = Path(__file__).parent

VARIANT_LABELS = {"cpu": "CPU", "pim-v2": "PIM-v2\n(PIM bitarray)", "pim-v3": "PIM-v3\n(PIM hash+bitarray)"}
VARIANT_COLORS = {"cpu": "#4878CF", "pim-v2": "#6ACC65", "pim-v3": "#D65F5F"}
M_LABELS = {1048576: "$2^{20}$", 8388608: "$2^{23}$", 67108864: "$2^{26}$"}
K_STYLES = {3: ("o", "-"), 5: ("s", "--"), 7: ("^", ":")}

df = pd.read_csv(RESULTS)
df["m_label"] = df["m"].map(M_LABELS)
df["insert_eps_B"] = df["insert_throughput_eps"] / 1e9
df["query_eps_B"] = df["query_throughput_eps"] / 1e9

M_VALS = sorted(df["m"].unique())
K_VALS = sorted(df["k"].unique())
LF_VALS = sorted(df["load_factor"].unique())
VARIANTS = ["cpu", "pim-v2", "pim-v3"]

plt.rcParams.update({"font.size": 11, "axes.titlesize": 12, "figure.dpi": 150})


# ── Figure 1: Insert & Query Throughput – grouped bar, k=5, load=0.125 ────────
def fig_throughput_bars():
    sub = df[(df["k"] == 5) & (df["load_factor"] == 0.125)]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=False)
    x = np.arange(len(M_VALS))
    width = 0.25
    for ax, col, title in zip(axes,
                               ["insert_eps_B", "query_eps_B"],
                               ["Insert Throughput", "Query Throughput"]):
        for i, var in enumerate(VARIANTS):
            vals = [sub[(sub["variant"] == var) & (sub["m"] == m)][col].values[0]
                    for m in M_VALS]
            bars = ax.bar(x + i * width, vals, width,
                          label=var.upper(), color=VARIANT_COLORS[var], edgecolor="white")
        ax.set_xticks(x + width)
        ax.set_xticklabels([M_LABELS[m] for m in M_VALS])
        ax.set_xlabel("Bit-array size m")
        ax.set_ylabel("Throughput (B ops/s)")
        ax.set_title(f"{title}  (k=5, load=0.125)")
        ax.legend(title="Variant")
        ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:.1f}B"))
        ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(OUT / "fig1_throughput_bars.png")
    plt.close(fig)
    print("fig1_throughput_bars.png")


# ── Figure 2: Throughput vs load factor – all variants, m=2^23, k=5 ──────────
def fig_throughput_vs_load():
    sub = df[(df["m"] == 8388608) & (df["k"] == 5)]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, col, title in zip(axes,
                               ["insert_eps_B", "query_eps_B"],
                               ["Insert Throughput", "Query Throughput"]):
        for var in VARIANTS:
            d = sub[sub["variant"] == var].sort_values("load_factor")
            ax.plot(d["load_factor"], d[col],
                    marker="o", color=VARIANT_COLORS[var], label=var.upper(), linewidth=2)
        ax.set_xlabel("Load factor (n/m)")
        ax.set_ylabel("Throughput (B ops/s)")
        ax.set_title(f"{title}  (m=$2^{{23}}$, k=5)")
        ax.legend(title="Variant")
        ax.set_xticks(LF_VALS)
    fig.tight_layout()
    fig.savefig(OUT / "fig2_throughput_vs_load.png")
    plt.close(fig)
    print("fig2_throughput_vs_load.png")


# ── Figure 3: PIM energy vs m – insert & query, all k, load=0.125 ────────────
def fig_energy_vs_m():
    sub = df[(df["variant"].isin(["pim-v2", "pim-v3"])) & (df["load_factor"] == 0.125)]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, col, title in zip(axes,
                               ["insert_energy_mj", "query_energy_mj"],
                               ["Insert Energy", "Query Energy"]):
        for var in ["pim-v2", "pim-v3"]:
            for k in K_VALS:
                d = sub[(sub["variant"] == var) & (sub["k"] == k)].sort_values("m")
                marker, linestyle = K_STYLES[k]
                ax.plot(range(len(M_VALS)), d[col].values,
                        marker=marker, linestyle=linestyle,
                        color=VARIANT_COLORS[var],
                        label=f"{var.upper()} k={k}", linewidth=1.8)
        ax.set_xticks(range(len(M_VALS)))
        ax.set_xticklabels([M_LABELS[m] for m in M_VALS])
        ax.set_xlabel("Bit-array size m")
        ax.set_ylabel("Energy (mJ)")
        ax.set_title(f"{title}  (load=0.125)")
        ax.legend(fontsize=8, ncol=2)
        ax.set_ylim(bottom=0)
    fig.tight_layout()
    fig.savefig(OUT / "fig3_energy_vs_m.png")
    plt.close(fig)
    print("fig3_energy_vs_m.png")


# ── Figure 4: FPR vs load factor for each k (CPU only – same for all variants)
def fig_fpr_vs_load():
    sub = df[(df["variant"] == "cpu") & (df["m"] == 8388608)]
    fig, ax = plt.subplots(figsize=(7, 5))
    for k in K_VALS:
        d = sub[sub["k"] == k].sort_values("load_factor")
        marker, linestyle = K_STYLES[k]
        ax.plot(d["load_factor"], d["fpr"],
                marker=marker, linestyle=linestyle,
                linewidth=2, label=f"k={k}")
    ax.set_xlabel("Load factor (n/m)")
    ax.set_ylabel("False positive rate")
    ax.set_title("FPR vs load factor  (m=$2^{23}$, identical across variants)")
    ax.legend(title="Hash functions")
    ax.set_xticks(LF_VALS)
    ax.yaxis.set_major_formatter(ticker.PercentFormatter(xmax=1, decimals=1))
    fig.tight_layout()
    fig.savefig(OUT / "fig4_fpr_vs_load.png")
    plt.close(fig)
    print("fig4_fpr_vs_load.png")


# ── Figure 5: Energy-throughput trade-off scatter (PIM variants, all configs) ─
def fig_energy_tradeoff():
    sub = df[df["variant"].isin(["pim-v2", "pim-v3"])]
    fig, ax = plt.subplots(figsize=(8, 6))
    for var in ["pim-v2", "pim-v3"]:
        d = sub[sub["variant"] == var]
        sc = ax.scatter(d["insert_eps_B"], d["insert_energy_mj"],
                        c=d["m"].map({m: i for i, m in enumerate(M_VALS)}),
                        cmap="viridis", marker=("o" if var == "pim-v2" else "^"),
                        s=60, alpha=0.85, label=var.upper(),
                        edgecolors=VARIANT_COLORS[var], linewidths=1.2)
    ax.set_xlabel("Insert Throughput (B ops/s)")
    ax.set_ylabel("Insert Energy (mJ)")
    ax.set_title("Energy vs Throughput trade-off (PIM variants)")
    ax.legend(title="Variant")
    cbar = fig.colorbar(sc, ax=ax, ticks=[0, 1, 2])
    cbar.ax.set_yticklabels([M_LABELS[m] for m in M_VALS])
    cbar.set_label("m")
    fig.tight_layout()
    fig.savefig(OUT / "fig5_energy_tradeoff.png")
    plt.close(fig)
    print("fig5_energy_tradeoff.png")


# ── Table 1: Summary – best config per variant (highest insert throughput) ────
def table_best_config():
    rows = []
    for var in VARIANTS:
        d = df[df["variant"] == var]
        best = d.loc[d["insert_throughput_eps"].idxmax()]
        rows.append({
            "Variant":        var.upper(),
            "m":              M_LABELS[best["m"]],
            "k":              int(best["k"]),
            "Load":           best["load_factor"],
            "Insert (B/s)":   f"{best['insert_eps_B']:.2f}",
            "Query (B/s)":    f"{best['query_eps_B']:.2f}",
            "FPR":            f"{best['fpr']:.4f}",
            "Ins. E (mJ)":    f"{best['insert_energy_mj']:.4f}",
        })
    tbl = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(11, 1.8))
    ax.axis("off")
    t = ax.table(cellText=tbl.values, colLabels=tbl.columns,
                 cellLoc="center", loc="center")
    t.auto_set_font_size(False)
    t.set_fontsize(10)
    t.scale(1, 1.6)
    for (r, c), cell in t.get_celld().items():
        if r == 0:
            cell.set_facecolor("#2C4770")
            cell.set_text_props(color="white", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#EEF2FA")
    ax.set_title("Table 1 – Best Insert Throughput per Variant", pad=12, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT / "table1_best_config.png", bbox_inches="tight")
    plt.close(fig)
    print("table1_best_config.png")


# ── Table 2: Energy comparison at fixed (m=2^23, k=5, load=0.125) ─────────────
def table_energy_comparison():
    sub = df[(df["m"] == 8388608) & (df["k"] == 5) & (df["load_factor"] == 0.125)]
    rows = []
    for var in VARIANTS:
        d = sub[sub["variant"] == var].iloc[0]
        rows.append({
            "Variant":         var.upper(),
            "n":               int(d["n"]),
            "Insert (B/s)":    f"{d['insert_eps_B']:.3f}",
            "Query (B/s)":     f"{d['query_eps_B']:.3f}",
            "FPR":             f"{d['fpr']:.4f}",
            "Insert E (mJ)":   f"{d['insert_energy_mj']:.4f}",
            "Query E (mJ)":    f"{d['query_energy_mj']:.4f}",
        })
    tbl = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(11, 1.8))
    ax.axis("off")
    t = ax.table(cellText=tbl.values, colLabels=tbl.columns,
                 cellLoc="center", loc="center")
    t.auto_set_font_size(False)
    t.set_fontsize(10)
    t.scale(1, 1.6)
    for (r, c), cell in t.get_celld().items():
        if r == 0:
            cell.set_facecolor("#2C4770")
            cell.set_text_props(color="white", fontweight="bold")
        elif r % 2 == 0:
            cell.set_facecolor("#EEF2FA")
    ax.set_title("Table 2 – Comparison at m=$2^{23}$, k=5, load=0.125", pad=12, fontsize=12)
    fig.tight_layout()
    fig.savefig(OUT / "table2_energy_comparison.png", bbox_inches="tight")
    plt.close(fig)
    print("table2_energy_comparison.png")


if __name__ == "__main__":
    fig_throughput_bars()
    fig_throughput_vs_load()
    fig_energy_vs_m()
    fig_fpr_vs_load()
    fig_energy_tradeoff()
    table_best_config()
    table_energy_comparison()
    print("Done — all outputs written to", OUT)
