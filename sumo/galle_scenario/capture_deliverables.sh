#!/usr/bin/env bash
# ============================================================
# SHIELD-GH / SDVN  —  Task-4 deliverable capture helper
#
# Supervisor requirements (01/07/2026) — capture & save screenshots:
#   1) OSM map screenshot of the selected dense city area
#   2) Screenshot of 200-vehicle selection (100 cars + 100 others)
#   3) 10 s clip of the SUMO simulation (>=190 vehicles, not stuck)
#   4) The imported TCL mobility file
#   5) 10 s clip of the NetAnim mobility trace (with 64 RSUs overlaid)
#
# This script opens each tool so you can record the screenshots / clips.
# It does NOT auto-record video (do that with your desktop recorder, e.g.
# `Ctrl+Shift+R` on GNOME, OBS, or SimpleScreenRecorder).
#
# Usage:
#   bash capture_deliverables.sh sumo      # open SUMO-GUI for the 10 s clip
#   bash capture_deliverables.sh netanim   # open NetAnim on the XML
#   bash capture_deliverables.sh osm       # print the OSM link + area
#   bash capture_deliverables.sh verify    # re-print the fleet/flow stats
# ============================================================
set -u
export SUMO_HOME=/home/sdvn_ssh/.local/lib/python3.10/site-packages/sumo
export PATH=$HOME/.local/bin:$PATH
export PROJ_LIB=$SUMO_HOME/data/proj PROJ_DATA=$SUMO_HOME/data/proj
HERE="$(cd "$(dirname "$0")" && pwd)"
NS3="$(cd "$HERE/../../.." && pwd)"          # .../ns-3.35
NETANIM="$NS3/../netanim-3.108/NetAnim"

cd "$HERE"

case "${1:-help}" in

  osm)
    echo "=== [Deliverable 1] OSM map of the selected dense city area ==="
    echo "City : Galle, Sri Lanka (dense urban centre, many crossing/overlapping roads)"
    echo "Area : 2 km x 2 km (measured from OSM)"
    echo "BBox (S,W,N,E): $(cat ../bbox.txt 2>/dev/null || echo 'see bbox.txt')"
    echo "OSM link: https://www.openstreetmap.org/#map=15/6.0535/80.2210"
    echo ">> Open the link, frame the 2x2 km area, screenshot -> save as galle_osm.png"
    ;;

  fleet)
    echo "=== [Deliverable 2] 200-vehicle selection (100 cars + 100 others) ==="
    echo "Fleet mix in galle.rou.xml:"
    for t in car bus lorry van truck; do
      printf "  %-6s : %d\n" "$t" "$(grep -c "type=\"$t\"" galle.rou.xml)"
    done
    echo "  TOTAL  : $(grep -c '<vehicle ' galle.rou.xml)"
    echo ">> Screenshot this table AND the SUMO-GUI vehicle list to prove the mix."
    ;;

  sumo)
    echo "=== [Deliverable 3] SUMO-GUI 10 s clip (>=190 vehicles) ==="
    echo "Start recording your screen, then let it run ~t=30..40 s (>=190 vehicles)."
    echo "Tip: set delay ~50 ms in the GUI toolbar so the 10 s of sim = ~10 s clip."
    echo "Launching sumo-gui..."
    sumo-gui -c galle.sumocfg --window-size 1600,1000 --delay 50 \
             --start false --quit-on-end false
    ;;

  netanim)
    echo "=== [Deliverable 5] NetAnim 10 s clip (200 vehicles + 64 RSUs) ==="
    XML="$HERE/galle_netanim.xml"
    if [ ! -f "$XML" ]; then
      echo "galle_netanim.xml missing — regenerating..."
      export LD_LIBRARY_PATH="$NS3/build/lib:$NS3/build:${LD_LIBRARY_PATH:-}"
      ( cd "$NS3" && ./build/scratch/galle_netanim \
          --tcl="$HERE/galle_mobility.tcl" --anim="$XML" --dur=10 )
    fi
    echo "Open File -> $XML in NetAnim, press Play, record the 10 s clip."
    if [ -x "$NETANIM" ]; then "$NETANIM" "$XML" &
    else echo "NetAnim binary not found at $NETANIM — open it manually."; fi
    ;;

  tcl)
    echo "=== [Deliverable 4] Imported TCL mobility file ==="
    ls -la "$HERE/galle_mobility.tcl"
    echo "nodes: $(grep -oE '\$node_\([0-9]+\)' galle_mobility.tcl | sort -u | wc -l)"
    echo "head:"; head -8 galle_mobility.tcl
    ;;

  verify)
    echo "=== Fleet / flow verification (warm-up t>=30 excluded) ==="
    python3 - <<'PY'
import xml.etree.ElementTree as ET, statistics
r=ET.parse('galle_summary.xml').getroot()
run=[];spd=[];below=0;tot=0
for s in r.findall('step'):
    t=float(s.get('time'))
    if t<30: continue
    tot+=1; rn=int(s.get('running')); run.append(rn); spd.append(float(s.get('meanSpeed')))
    if rn<190: below+=1
print(f"concurrent vehicles: min={min(run)} max={max(run)} mean={statistics.mean(run):.1f}")
print(f"exceeds 190 for {100*(1-below/tot):.1f}% of the 300s+ measurement window")
print(f"mean speed: {statistics.mean(spd)*3.6:.1f} km/h  (a moving vehicular network)")
last=r.findall('step')[-1]
print(f"collisions={last.get('collisions')} teleports={last.get('teleports')} end={last.get('time')}s")
PY
    ;;

  *)
    echo "usage: bash capture_deliverables.sh {osm|fleet|sumo|netanim|tcl|verify}"
    ;;
esac
