#!/usr/bin/env python3
"""
Task 9.5 -- ablation figure generator.

Reads ablation_results.csv (written by ablation_driver.py) and emits one
publication figure per ablation plus a combined summary bar chart.

Design notes (dataviz skill):
  * Two series only -- "Full system" (control) vs "Ablated" -- so identity is
    carried by the first two categorical slots in fixed order: blue #2a78d6,
    orange #eb6834. Never cycled, never reassigned by rank.
  * One y-axis (MCC). No dual axes anywhere.
  * Legend always present (>=2 series) AND markers differ (o vs s), so
    identity is never colour-alone.
  * Recessive grid/axes in muted ink; data marks carry the emphasis.
  * A12 is a single-arm sweep (the x variable IS the ablation), so it is
    drawn as one series with direct labels.
"""
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
CSV = os.path.join(HERE, "ablation_results.csv")
OUT = HERE

# --- palette (dataviz reference instance, light surface) -------------------
C_CONTROL = "#2a78d6"   # categorical slot 1 (blue)
C_ABLATED = "#eb6834"   # categorical slot 2 (orange)
INK       = "#0b0b0b"
MUTED     = "#898781"
GRID      = "#e1e0d9"
BASELINE  = "#c3c2b7"
SURFACE   = "#fcfcfb"

XLABEL = {
    "speed_kmh":     "Vehicle speed $v$ (km/h)",
    "drop_rate_pct": r"Grey-hole drop rate $\rho$ (%)",
    "n_controllers": "Number of controllers $M$",
}

TITLE = {
    "A1":  "A1 — MATD handoff correction",
    "A4":  "A4 — LLM semantic scorer ($\\mu_2 = 0$)",
    "A7":  "A7 — DEBSC cryptographic (ZKP) gate",
    "A12": "A12 — Multi-controller architecture",
    "SIG": "S1–S6 signatures (reference bound)",
}


def style(ax):
    ax.set_facecolor(SURFACE)
    ax.grid(True, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(BASELINE)
        ax.spines[s].set_linewidth(1.0)
    ax.tick_params(colors=MUTED, labelsize=9)
    for lbl in ax.get_xticklabels() + ax.get_yticklabels():
        lbl.set_color(MUTED)


def load():
    rows = []
    if not os.path.exists(CSV):
        raise SystemExit(f"missing {CSV} -- run ablation_driver.py first")
    with open(CSV, newline="") as fh:
        for r in csv.DictReader(fh):
            if r.get("status") != "ok" or not r.get("M1_MCC"):
                continue
            try:
                r["x"] = float(r["x"])
                r["M1_MCC"] = float(r["M1_MCC"])
                r["CP_MCC"] = float(r["CP_MCC"]) if r.get("CP_MCC") else None
            except ValueError:
                continue
            rows.append(r)
    return rows


def series(rows, ab, arm):
    """Mean MCC per x for one arm (averages over seeds if several)."""
    acc = defaultdict(list)
    for r in rows:
        if r["ablation"] == ab and r["arm"] == arm:
            acc[r["x"]].append(r["M1_MCC"])
    xs = sorted(acc)
    return xs, [sum(acc[x]) / len(acc[x]) for x in xs]


def plot_two_arm(rows, ab):
    xs_c, ys_c = series(rows, ab, "control")
    xs_a, ys_a = series(rows, ab, "ablated")
    if not xs_c and not xs_a:
        return None
    xname = next(r["xname"] for r in rows if r["ablation"] == ab)

    fig, ax = plt.subplots(figsize=(6.2, 3.9), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    style(ax)

    ax.plot(xs_c, ys_c, marker="o", markersize=7, linewidth=2,
            color=C_CONTROL, label="Full system", zorder=3,
            markeredgecolor=SURFACE, markeredgewidth=1.5)
    ax.plot(xs_a, ys_a, marker="s", markersize=7, linewidth=2,
            color=C_ABLATED, label="Ablated", zorder=3,
            markeredgecolor=SURFACE, markeredgewidth=1.5)

    # Shade the contribution of the removed component.
    if xs_c == xs_a:
        ax.fill_between(xs_c, ys_a, ys_c, color=C_CONTROL, alpha=0.10,
                        zorder=1, linewidth=0)

    ax.set_xlabel(XLABEL.get(xname, xname), color=INK, fontsize=10)
    ax.set_ylabel("Detection quality (M1 — MCC)", color=INK, fontsize=10)
    ax.set_title(TITLE.get(ab, ab), color=INK, fontsize=11,
                 fontweight="bold", loc="left", pad=10)
    ax.set_ylim(0, 1.0)
    ax.set_xticks(xs_c or xs_a)
    leg = ax.legend(frameon=False, fontsize=9, loc="lower left")
    for t in leg.get_texts():
        t.set_color(INK)

    path = os.path.join(OUT, f"ablation_{ab}.png")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path


def plot_a12(rows):
    """A12: the x sweep IS the ablation (M=1 is the ablated architecture).
    Node-level and controller-plane MCC are two different measures, so they
    are drawn as two stacked panels -- never a dual axis."""
    acc_n, acc_c = defaultdict(list), defaultdict(list)
    for r in rows:
        if r["ablation"] != "A12":
            continue
        acc_n[r["x"]].append(r["M1_MCC"])
        if r["CP_MCC"] is not None:
            acc_c[r["x"]].append(r["CP_MCC"])
    xs = sorted(acc_n)
    if not xs:
        return None
    yn = [sum(acc_n[x]) / len(acc_n[x]) for x in xs]
    yc = [sum(acc_c[x]) / len(acc_c[x]) for x in xs if x in acc_c]

    fig, axes = plt.subplots(2, 1, figsize=(6.2, 5.6), dpi=200, sharex=True)
    fig.patch.set_facecolor(SURFACE)

    for ax, ys, lab, col in (
            (axes[0], yn, "Node-level (M1 — MCC)", C_CONTROL),
            (axes[1], yc, "Controller-plane (LW-CP-Det MCC)", C_ABLATED)):
        style(ax)
        if not ys:
            continue
        ax.plot(xs[:len(ys)], ys, marker="o", markersize=7, linewidth=2,
                color=col, zorder=3, markeredgecolor=SURFACE,
                markeredgewidth=1.5)
        for x, y in zip(xs[:len(ys)], ys):
            ax.annotate(f"{y:.2f}", (x, y), textcoords="offset points",
                        xytext=(0, 9), ha="center", fontsize=8, color=INK)
        ax.set_ylabel(lab, color=INK, fontsize=9)
        ax.set_ylim(0, 1.15)

    axes[0].set_title(TITLE["A12"], color=INK, fontsize=11,
                      fontweight="bold", loc="left", pad=10)
    axes[1].set_xlabel(XLABEL["n_controllers"], color=INK, fontsize=10)
    axes[1].set_xticks(xs)

    path = os.path.join(OUT, "ablation_A12.png")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path


def plot_summary(rows):
    """Mean MCC drop caused by removing each component, across its sweep."""
    deltas = []
    for ab in ("A1", "A4", "A7", "SIG"):
        xs_c, ys_c = series(rows, ab, "control")
        xs_a, ys_a = series(rows, ab, "ablated")
        common = sorted(set(xs_c) & set(xs_a))
        if not common:
            continue
        dc = {x: y for x, y in zip(xs_c, ys_c)}
        da = {x: y for x, y in zip(xs_a, ys_a)}
        d = sum(dc[x] - da[x] for x in common) / len(common)
        deltas.append((ab, d))
    if not deltas:
        return None
    deltas.sort(key=lambda t: t[1], reverse=True)

    labels = [d[0] for d in deltas]
    vals = [d[1] for d in deltas]

    fig, ax = plt.subplots(figsize=(6.2, 3.4), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    style(ax)
    bars = ax.bar(labels, vals, color=C_CONTROL, width=0.55, zorder=3)
    # 4px-equivalent rounded data-ends are not available for plain bars in
    # matplotlib; keep square ends but hold the 2px surface gap via width.
    for b, v in zip(bars, vals):
        ax.annotate(f"{v:+.3f}", (b.get_x() + b.get_width() / 2, v),
                    textcoords="offset points", xytext=(0, 4),
                    ha="center", fontsize=9, color=INK)
    ax.axhline(0, color=BASELINE, linewidth=1.0, zorder=2)
    ax.set_ylabel("Mean MCC lost when removed", color=INK, fontsize=10)
    ax.set_xlabel("Ablated component", color=INK, fontsize=10)
    ax.set_title("Component contribution to detection quality",
                 color=INK, fontsize=11, fontweight="bold", loc="left", pad=10)

    path = os.path.join(OUT, "ablation_summary.png")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path


def main():
    rows = load()
    made = []
    for ab in ("A1", "A4", "A7", "SIG"):
        p = plot_two_arm(rows, ab)
        if p:
            made.append(p)
    p = plot_a12(rows)
    if p:
        made.append(p)
    p = plot_summary(rows)
    if p:
        made.append(p)
    for m in made:
        print("wrote", m)
    if not made:
        print("no figures -- CSV had no usable rows")


if __name__ == "__main__":
    main()
