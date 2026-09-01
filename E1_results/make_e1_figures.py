#!/usr/bin/env python3
"""
Generate E1 figures + LaTeX table from e1_m1_results.csv.

Produces:
  e1_mcc_heatmaps.png   -- 5 panels (one per system), shared colour scale,
                           x = drop rate rho_a, y = attacker penetration p
  e1_mcc_lines.png      -- MCC vs rho_a, one line per system, at p=40%
  e1_results_table.tex  -- LaTeX table of the full grid
  e1_summary.txt        -- plain-text summary for quick reading

Only M1 (MCC) is plotted: M2/M3/M4/M5 are not implemented in routing.cc.
"""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "e1_m1_results.csv")

P_VALUES = [0, 20, 40, 60, 80, 100]
RHO_VALUES = [0, 20, 40, 60, 80, 100]
SYSTEMS = ["shieldgh_full", "shieldgh_lite", "b1_malik", "b2_vcbc", "b3_rf"]
LABELS = {
    "shieldgh_full": "SHIELD-GH (full)",
    "shieldgh_lite": "SHIELD-GH (lightweight)",
    "b1_malik": "B1: Malik (2023)",
    "b2_vcbc": "B2: VCBC (2024)",
    "b3_rf": "B3: FL-BERT/RF (2024)",
}


def load():
    """Return (mcc_grid, acc_grid, nrows).

    Both grids are indexed [p_index, rho_index] per system.

    Note on the p=0 row: with zero attackers there are no positives, so MCC
    is 0/0 and routing.cc reports 0.00. That is NOT a detection failure --
    accuracy on that row is 94-98%, i.e. the detectors are correctly leaving
    legitimate nodes alone. The p=0 row is therefore reported as a
    false-positive check using accuracy, and masked out of the MCC figures
    so it does not read as "all systems scored zero".
    """
    if not os.path.exists(CSV_PATH):
        sys.exit(f"missing {CSV_PATH}")
    shape = (len(P_VALUES), len(RHO_VALUES))
    grid = {s: np.full(shape, np.nan) for s in SYSTEMS}
    acc = {s: np.full(shape, np.nan) for s in SYSTEMS}
    nrows = 0
    for row in csv.DictReader(open(CSV_PATH)):
        s = row["system"]
        if s not in grid:
            continue
        try:
            pi = P_VALUES.index(int(row["p"]))
            ri = RHO_VALUES.index(int(row["rho_a"]))
        except ValueError:
            continue
        v = row.get("M1_MCC", "")
        if v not in ("", None):
            try:
                fv = float(v)
                # p=0 -> MCC undefined (0/0); leave as NaN in the MCC grid.
                grid[s][pi, ri] = np.nan if int(row["p"]) == 0 else fv
            except ValueError:
                pass
        av = row.get("M1_ACC", "")
        if av not in ("", None):
            try:
                acc[s][pi, ri] = float(av)
            except ValueError:
                pass
        nrows += 1
    return grid, acc, nrows


def fp_table(acc):
    """p=0 row: no attackers, so accuracy is a direct false-positive check."""
    lines = ["", "False-positive check (p=0%, no attackers present):",
             "  higher accuracy = fewer legitimate nodes wrongly flagged"]
    for s in SYSTEMS:
        row = acc[s][P_VALUES.index(0), :]
        ok = row[~np.isnan(row)]
        if ok.size:
            lines.append(f"  {LABELS[s]:28s} accuracy mean={ok.mean():.2f}% "
                         f"min={ok.min():.2f}% max={ok.max():.2f}%")
        else:
            lines.append(f"  {LABELS[s]:28s} no data")
    return "\n".join(lines)


def heatmaps(grid):
    fig, axes = plt.subplots(1, len(SYSTEMS), figsize=(4.0 * len(SYSTEMS), 4.4))
    parts = [g[~np.isnan(g)].ravel() for g in grid.values()
             if np.any(~np.isnan(g))]
    vals = np.concatenate(parts) if parts else np.array([0.0, 1.0])
    vmin = float(np.nanmin(vals)) if vals.size else 0.0
    vmax = float(np.nanmax(vals)) if vals.size else 1.0
    if abs(vmax - vmin) < 1e-9:
        vmin, vmax = vmin - 0.05, vmax + 0.05

    im = None
    for ax, s in zip(np.atleast_1d(axes), SYSTEMS):
        g = grid[s]
        im = ax.imshow(g, origin="lower", aspect="auto", cmap="viridis",
                       vmin=vmin, vmax=vmax)
        ax.set_xticks(range(len(RHO_VALUES)))
        ax.set_xticklabels([str(r) for r in RHO_VALUES])
        ax.set_yticks(range(len(P_VALUES)))
        ax.set_yticklabels([str(p) for p in P_VALUES])
        ax.set_xlabel(r"drop rate $\rho_a$ (%)")
        ax.set_title(LABELS[s], fontsize=10)
        for i in range(len(P_VALUES)):
            for j in range(len(RHO_VALUES)):
                v = g[i, j]
                txt = "n/a" if np.isnan(v) else f"{v:.2f}"
                ax.text(j, i, txt, ha="center", va="center", fontsize=7,
                        color="white" if (np.isnan(v) or v < (vmin + vmax) / 2)
                        else "black")
    np.atleast_1d(axes)[0].set_ylabel(r"attacker penetration $p$ (%)")
    fig.suptitle("E1: Detection quality (M1 = MCC) over the attack grid "
                 f"(N=20, variant S1)", fontsize=12)
    fig.colorbar(im, ax=np.atleast_1d(axes).tolist(), shrink=0.85, label="MCC")
    out = os.path.join(HERE, "e1_mcc_heatmaps.png")
    fig.savefig(out, dpi=160, bbox_inches="tight")
    print("wrote", out)
    plt.close(fig)


def lineplot(grid, p_focus=40):
    if p_focus not in P_VALUES:
        return
    pi = P_VALUES.index(p_focus)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for s in SYSTEMS:
        y = grid[s][pi, :]
        ax.plot(RHO_VALUES, y, marker="o", label=LABELS[s])
    ax.set_xlabel(r"drop rate $\rho_a$ (%)")
    ax.set_ylabel("MCC")
    ax.set_title(f"E1: MCC vs drop rate at attacker penetration p={p_focus}%")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    out = os.path.join(HERE, "e1_mcc_lines.png")
    fig.savefig(out, dpi=160, bbox_inches="tight")
    print("wrote", out)
    plt.close(fig)


def latex(grid):
    lines = [
        r"\begin{table}[H]",
        r"\centering\small",
        r"\caption{E1: Detection quality (M1, Matthews Correlation Coefficient) "
        r"across the attacker-penetration $\times$ drop-rate grid "
        r"($N=20$, attack variant S1/DP-FR). Only M1 is reported; "
        r"M2--M5 are not instrumented in the simulator.}",
        r"\label{tab:e1_mcc}",
        r"\begin{tabular}{|l|l|" + "c|" * len(RHO_VALUES) + "}",
        r"\hline",
        r"\textbf{System} & \textbf{$p$ (\%)} & "
        + " & ".join([rf"$\rho_a$={r}\%" for r in RHO_VALUES]) + r" \\",
        r"\hline",
    ]
    for s in SYSTEMS:
        for i, p in enumerate(P_VALUES):
            cells = []
            for j in range(len(RHO_VALUES)):
                v = grid[s][i, j]
                cells.append("n/a" if np.isnan(v) else f"{v:.2f}")
            name = LABELS[s].replace("&", r"\&") if i == 0 else ""
            lines.append(f"{name} & {p} & " + " & ".join(cells) + r" \\")
        lines.append(r"\hline")
    lines += [r"\end{tabular}", r"\end{table}"]
    out = os.path.join(HERE, "e1_results_table.tex")
    open(out, "w").write("\n".join(lines) + "\n")
    print("wrote", out)


def summary(grid, acc, nrows):
    ls = [f"E1 summary -- {nrows} rows loaded", "",
          "Detection quality (M1 = MCC), attacker rows p>0 only:"]
    for s in SYSTEMS:
        g = grid[s]
        ok = g[~np.isnan(g)]
        if ok.size:
            ls.append(f"  {LABELS[s]:28s} cells={ok.size:3d}/30 "
                      f"mean MCC={ok.mean():.3f} min={ok.min():.3f} max={ok.max():.3f}")
        else:
            ls.append(f"  {LABELS[s]:28s} NO DATA")
    ls.append(fp_table(acc))
    txt = "\n".join(ls)
    open(os.path.join(HERE, "e1_summary.txt"), "w").write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    grid, acc, nrows = load()
    heatmaps(grid)
    lineplot(grid)
    latex(grid)
    summary(grid, acc, nrows)
