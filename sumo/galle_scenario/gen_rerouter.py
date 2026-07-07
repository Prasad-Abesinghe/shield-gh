#!/usr/bin/env python3
"""
SHIELD-GH Galle scenario : generate a city-wide rerouter additional file.

Supervisor requires >=190 vehicles to be CONCURRENTLY present in the network
(NetAnim must display ~200). By default a SUMO vehicle leaves the simulation
as soon as it reaches its route's final edge, so with 200 short trips only a
few tens are ever on the road at once.

This rerouter is attached to (almost) every drivable edge and, via
<destProbReroute>, sends any vehicle that is about to arrive to a fresh random
destination edge for the whole 0..END window. Vehicles therefore keep driving
around the 2 km x 2 km city and stay in the network for the full 600 s run,
so the concurrent count stays at ~200.

We deliberately EXCLUDE fringe / dead-end edges as reroute *destinations*
(edges with no successor) so vehicles are not sent into cul-de-sacs where they
would arrive and vanish anyway; every drivable edge still carries the rerouter
as a trigger location.
"""
import xml.etree.ElementTree as ET

NET = "galle.net.xml"
OUT = "rerouters.add.xml"
END = 600

net = ET.parse(NET).getroot()

# Collect non-internal edges and their allowed successors.
edges = {}
for e in net.findall("edge"):
    eid = e.get("id")
    if eid is None or eid.startswith(":"):   # skip internal junction edges
        continue
    func = e.get("function")
    if func == "internal":
        continue
    edges[eid] = e

# Build successor map from connections to know which edges are "through" edges
# (have at least one outgoing connection) — good reroute destinations.
has_succ = set()
for c in net.findall("connection"):
    frm = c.get("from")
    if frm and not frm.startswith(":"):
        has_succ.add(frm)

# Destinations = drivable through-edges that allow passenger vehicles.
def allows_passenger(e):
    # if the edge has any lane that disallows passenger, we still keep it;
    # SUMO will just not reroute a vehicle onto a lane it cannot use.
    return True

dest_edges = [eid for eid in edges if eid in has_succ and allows_passenger(edges[eid])]
if not dest_edges:
    dest_edges = list(edges.keys())

root = ET.Element("additional")

# One rerouter interval, shared destination distribution, applied to all edges.
# Using a single <rerouter> with edges="e1 e2 ..." keeps the file compact.
trigger_edges = " ".join(sorted(edges.keys()))
rr = ET.SubElement(root, "rerouter")
rr.set("id", "cityLoop")
rr.set("edges", trigger_edges)
rr.set("probability", "1.0")

interval = ET.SubElement(rr, "interval")
interval.set("begin", "0")
interval.set("end", str(END))
# uniform destination probability across all through-edges
for de in dest_edges:
    dp = ET.SubElement(interval, "destProbReroute")
    dp.set("id", de)
    dp.set("probability", "1")

ET.indent(root, space="  ")
ET.ElementTree(root).write(OUT, encoding="UTF-8", xml_declaration=True)
print(f"rerouter written -> {OUT}: {len(edges)} trigger edges, "
      f"{len(dest_edges)} destination edges, active 0..{END}s")
