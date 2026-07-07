# SHIELD-GH / SDVN — Galle Real-World SUMO Scenario

Real-world vehicular mobility scenario for the ns-3.35 SDVN simulation, built
from OpenStreetMap data of **Galle, Sri Lanka**, with an 8×8 RSU grid overlaid
in ns-3/NetAnim.

## Selected area (Deliverable 1)

- **City:** Galle, Sri Lanka — dense urban centre with many overlapping /
  crossing roads and **284 real intersections**.
- **Centre:** 6.0535° N, 80.2210° E
- **Region:** measured from OSM as **2 km × 2 km**; the OSM was cropped to this
  exact bbox (`galle_2km.osm.xml`) and the resulting SUMO net spans
  **2097 m × 2120 m** (bbox in `../bbox.txt`).
- **Bounding box (S, W, N, E):** `6.044456, 80.211967, 6.062544, 80.230033`
- **OSM link:** https://www.openstreetmap.org/#map=15/6.0535/80.2210

## Fleet — 200 vehicles (Deliverable 2)

| Type  | Count | vClass    | maxSpeed | length |
|-------|-------|-----------|----------|--------|
| car   | 100   | passenger | 150 km/h | 4.5 m  |
| bus   | 25    | bus       | 150 km/h | 12.0 m |
| lorry | 25    | truck     | 150 km/h | 9.0 m  |
| van   | 25    | delivery  | 150 km/h | 5.5 m  |
| truck | 25    | truck     | 150 km/h | 16.5 m |

100 cars + 100 other vehicles = 200. All capped at **150 km/h**; vClass drives
which OSM edges each type may legally use. Vehicle IDs are `veh0..veh199`
(→ ns-3 node `i`).

## Keeping ≥190 vehicles concurrently present

The supervisor requires **≥190 vehicles on the road at once** (NetAnim must show
~200). By default SUMO vehicles leave as soon as they reach their destination,
so only ~70 were ever concurrent. The scenario now:

1. **inserts all 200 vehicles within the first 30 s** (warm-up), so ns-3 can
   safely start at **t = 30 s**; and
2. attaches a **city-wide rerouter** (`rerouters.add.xml`) that reroutes every
   vehicle about to arrive to a fresh random destination, so vehicles keep
   driving around the city for the full **600 s** run.

On the strict 2 km net this is reinforced by SUMO's **auto-rerouting device**
(`device.rerouting.*` in the config), which periodically hands every vehicle a
new destination while it drives, so vehicles almost never permanently arrive.

Measured result (warm-up t≥30 excluded): **min 188 / mean ≈195 / max 200**
concurrent vehicles, exceeding 190 for ~94 % of the run, mean network speed
**≈21 km/h**, 0 collisions — a moving, non-gridlocked vehicular network.
Anti-gridlock (`time-to-teleport=300`, junction impatience) clears the rare
priority-junction deadlock so vehicles never stay stuck.

## RSU grid (Deliverable 5)

64 RSUs on an **8×8 grid, 250 m apart** horizontally and vertically, centred in
the 2 km net (grid origin ≈ (174, 185), spanning [174..1924] × [185..1935] m),
are overlaid on the mobility trace by the ns-3 program `scratch/galle_netanim.cc`
(nodes 0–199 = vehicles, 200–263 = RSUs).

## Files

| File | Purpose |
|------|---------|
| `galle.osm.xml`        | Raw OSM data (API bbox export, has overhanging roads) |
| `galle_2km.osm.xml`    | OSM cropped to the exact 2×2 km bbox (ways trimmed at border) |
| `galle.net.xml`        | SUMO network from `galle_2km.osm.xml` (2097×2120 m) |
| `vtypes.add.xml`       | 5 vehicle-type definitions (+ junction impatience) |
| `rerouters.add.xml`    | City-wide rerouter (keeps ~200 vehicles looping) |
| `galle.rou.xml`        | 200 routed vehicles (`veh0..veh199`) |
| `galle.sumocfg`        | SUMO config (600 s, warm-up + anti-gridlock, FCD) |
| `galle_fcd.xml`        | Full mobility trace (600 s) |
| `galle_summary.xml`    | Per-step fleet summary (used for verification) |
| **`galle_mobility.tcl`** | **NS-2 TCL mobility trace (Deliverable 4)** — 200 nodes |
| **`galle_netanim.xml`**  | **NetAnim XML: 200 vehicles + 64 RSUs (Deliverable 5)** |
| `gen_fleet.sh`         | Regenerates the 200-vehicle fleet |
| `gen_rerouter.py`      | Builds the city-wide rerouter |
| `merge_fleet.py`       | Merges per-class trips → `veh{i}` route file |
| `capture_deliverables.sh` | Opens SUMO-GUI / NetAnim to record the clips |

## Reproduce end-to-end

```bash
export SUMO_HOME=$HOME/.local/lib/python3.10/site-packages/sumo
export PATH=$HOME/.local/bin:$PATH

# 0. (only if rebuilding the net) crop OSM to the exact 2x2 km bbox, then
#    netconvert galle_2km.osm.xml -> galle.net.xml  (see netconvert.log for flags)

# 1. (re)generate the 200-vehicle fleet + rerouter
bash gen_fleet.sh

# 2. run SUMO for 600 s (produces galle_fcd.xml, galle_summary.xml)
sumo -c galle.sumocfg

# 3. verify >=190 concurrent
bash capture_deliverables.sh verify

# 4. export the NS-2 TCL mobility trace (Deliverable 4)
python3 "$SUMO_HOME/tools/traceExporter.py" \
    --fcd-input galle_fcd.xml --ns2mobility-output galle_mobility.tcl

# 5. build + run the ns-3 NetAnim overlay (200 vehicles + 64 RSUs)
cd ../../..                                  # -> ns-3.35
./waf build --target=galle_netanim
LD_LIBRARY_PATH=$PWD/build/lib:$PWD/build ./build/scratch/galle_netanim \
    --tcl=scratch/sumo/galle_scenario/galle_mobility.tcl \
    --anim=scratch/sumo/galle_scenario/galle_netanim.xml --dur=10
```

## Capturing the screenshots / clips for the paper

```bash
bash capture_deliverables.sh osm      # 1) OSM map screenshot
bash capture_deliverables.sh fleet    # 2) 200-vehicle mix
bash capture_deliverables.sh sumo     # 3) SUMO-GUI 10 s clip (>=190 vehicles)
bash capture_deliverables.sh tcl      # 4) TCL mobility file
bash capture_deliverables.sh netanim  # 5) NetAnim 10 s clip (with RSUs)
```

Save the SUMO screenshot as `scratch/galle_sumo.png` and the NetAnim screenshot
as `scratch/galle_netanim.png` — the report's *Simulation Settings* section
(`main.tex`, Fig. `sim_env`) includes them as the two subfigures.

## ns-3 coupling

`../sumo_ns3_bridge.py galle` launches this scenario over TraCI and streams
per-vehicle speeds/positions to `../../results/sumo_speeds.csv`, consumed by the
MATD module via `read_ns3_speed_for_node(node_index)`.
