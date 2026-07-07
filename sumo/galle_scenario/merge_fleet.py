#!/usr/bin/env python3
"""
SHIELD-GH Galle scenario : merge per-class route files into one
fleet route file (galle.rou.xml) with veh0..veh199 IDs.

The ns-3 bridge (sumo_ns3_bridge.py) maps SUMO id 'veh{i}' -> ns-3 node i,
so the final vehicle IDs must be exactly veh0..veh199.
We keep the vType on each vehicle so the mix (car/bus/lorry/van/truck)
is preserved; only the *id* is renumbered.
"""
import xml.etree.ElementTree as ET

SOURCES = ["car", "bus", "lorry", "van", "truck"]

vehicles = []  # (depart, vtype, route_edges)
for t in SOURCES:
    root = ET.parse(f"trips_{t}.rou.xml").getroot()
    for v in root.findall("vehicle"):
        route = v.find("route")
        edges = route.get("edges")
        depart = float(v.get("depart"))
        # use the clean vtype from the SOURCE file (car/bus/lorry/van/truck),
        # not randomTrips' mangled '<name>__<vclass>' id. This keeps lorry vs
        # truck distinct even though both share vClass="truck".
        vehicles.append((depart, t, edges))

# sort by departure so the fleet is interleaved/mixed over time
vehicles.sort(key=lambda x: x[0])

out = ET.Element("routes")
out.set("{http://www.w3.org/2001/XMLSchema-instance}noNamespaceSchemaLocation",
        "http://sumo.dlr.de/xsd/routes_file.xsd")

# include the vType definitions inline so the route file is self-contained
vt_root = ET.parse("vtypes.add.xml").getroot()
for vt in vt_root.findall("vType"):
    out.append(vt)

counts = {}
for i, (depart, vtype, edges) in enumerate(vehicles):
    veh = ET.SubElement(out, "vehicle")
    veh.set("id", f"veh{i}")
    veh.set("type", vtype)
    veh.set("depart", f"{depart:.2f}")
    ET.SubElement(veh, "route").set("edges", edges)
    counts[vtype] = counts.get(vtype, 0) + 1

ET.indent(out, space="    ")
ET.ElementTree(out).write("galle.rou.xml", encoding="UTF-8", xml_declaration=True)

print(f"merged {len(vehicles)} vehicles -> galle.rou.xml")
print("fleet mix:", counts)
