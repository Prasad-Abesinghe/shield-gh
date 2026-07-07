#!/usr/bin/env bash
# ============================================================
# SHIELD-GH  Galle scenario : generate 200-vehicle mixed fleet
#   100 car | 25 bus | 25 lorry | 25 van | 25 truck
#
# Supervisor requirements (01/07/2026):
#   * >=190 vehicles CONCURRENTLY present (NetAnim must show ~200)
#   * NS-3 starts at t=30 s (SUMO needs warm-up to spawn all 200)
#   * SUMO runs for 600 s; vehicles must not get stuck / congested
#
# To keep ~200 vehicles alive for the whole 600 s (instead of them
# arriving at their destination and leaving the network) we:
#   1. insert ALL 200 vehicles within the first WARMUP=30 s, and
#   2. attach a rerouter (rerouters.add.xml) covering every edge that
#      reroutes any vehicle about to arrive to a fresh random edge,
#      so vehicles keep driving around the city for the full run.
#
# Uses randomTrips.py per vClass so each type only routes on edges it
# is legally allowed on, then the routes are merged + renumbered to
# veh0..veh199 (ns-3 bridge mapping).
# ============================================================
set -e
export SUMO_HOME=/home/sdvn_ssh/.local/lib/python3.10/site-packages/sumo
export PATH=$HOME/.local/bin:$PATH
RT="$SUMO_HOME/tools/randomTrips.py"
NET=galle.net.xml
WARMUP=30        # all trips inserted within the first 30 s (warm-up window)
SEED=42

# type -> count, vClass.  Insert this type's vehicles evenly over [0,WARMUP].
gen() {  # $1=type $2=count $3=vclass
  python3 "$RT" -n "$NET" \
    --vehicle-class "$3" \
    --prefix "${1}_" --vtype "$1" \
    -b 0 -e "$WARMUP" -p $(python3 -c "print($WARMUP/$2)") \
    --min-distance 1200 --max-distance 4000 --fringe-factor 1 \
    --allow-fringe.min-length 1000 \
    --seed $((SEED + ${#1})) \
    --validate \
    -r "trips_${1}.rou.xml" -o "trips_${1}.trips.xml" \
    --additional-files vtypes.add.xml 2>"rt_${1}.log" || { echo "FAIL $1"; tail -5 "rt_${1}.log"; exit 1; }
  echo "  $1: $(grep -c '<vehicle' trips_${1}.rou.xml) routes"
}

echo "Generating per-class routes (all inserted within ${WARMUP}s)..."
gen car   100 passenger
gen bus    25 bus
gen lorry  25 truck
gen van    25 delivery
gen truck  25 truck

echo "Building city-wide rerouter (keeps vehicles alive for the full run)..."
python3 gen_rerouter.py

echo "Merging + renumbering to veh0..veh199 ..."
python3 merge_fleet.py
echo "Done."
