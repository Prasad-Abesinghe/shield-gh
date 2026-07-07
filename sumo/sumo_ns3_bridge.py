# ============================================================
# SHIELD-GH SUMO-NS3 Bridge
# Connects SUMO vehicular mobility to NS-3 node positions.
# Provides realistic vehicle speeds for MATD (Eq. 3.4, 3.17).
# Usage: python sumo_ns3_bridge.py [highway|urban]
# ============================================================
import sys
import os
import csv
import time

try:
    import traci
    TRACI_AVAILABLE = True
except ImportError:
    TRACI_AVAILABLE = False
    print("Warning: TraCI not available — using dummy mobility data")


SPEED_LOG_PATH = "../../results/sumo_speeds.csv"
POSITION_LOG_PATH = "../../results/sumo_positions.csv"


def run_sumo_ns3_simulation(scenario: str = "highway",
                             max_steps: int = 6000) -> dict:
    """
    Run SUMO simulation and export vehicle speeds to CSV for NS-3 MATD.
    Returns final vehicle_speeds dict: {vehicle_id: speed_mps}

    NOTE: max_steps counts SUMO *steps*, not seconds. With step-length 0.1 s,
    a 600 s scenario needs 6000 steps. The loop also stops early once no more
    vehicles are expected, so this is just a safety cap.
    """
    if not TRACI_AVAILABLE:
        return _generate_dummy_speeds(scenario)

    scenario_dir = os.path.dirname(os.path.abspath(__file__))
    # Real-world Galle scenario lives in its own subfolder with a plain
    # '<name>.sumocfg'; the synthetic highway/urban use '<name>_scenario.sumocfg'.
    galle_cfg = os.path.join(scenario_dir, "galle_scenario", "galle.sumocfg")
    if scenario == "galle" and os.path.exists(galle_cfg):
        cfg_path = galle_cfg
    else:
        cfg_path = os.path.join(scenario_dir, f"{scenario}_scenario.sumocfg")

    # Prefer 'sumo' on PATH; fall back to the SUMO_HOME binary (pip install).
    sumo_bin = "sumo"
    if os.environ.get("SUMO_HOME"):
        cand = os.path.join(os.environ["SUMO_HOME"], "bin", "sumo")
        if os.path.exists(cand):
            sumo_bin = cand
        # Point PROJ at SUMO's bundled coordinate DB so geo-projection works
        # silently (otherwise: 'pj_obj_create: Cannot find proj.db' warnings).
        proj_dir = os.path.join(os.environ["SUMO_HOME"], "data", "proj")
        if os.path.isdir(proj_dir):
            os.environ.setdefault("PROJ_LIB", proj_dir)
            os.environ.setdefault("PROJ_DATA", proj_dir)

    sumo_cmd = [sumo_bin, "--configuration-file", cfg_path,
                "--no-step-log", "--time-to-teleport", "-1"]
    # Redirect FCD/netstate to bridge-specific (absolute) files so a TraCI run
    # never overwrites the authoritative standalone trace (galle_fcd.xml).
    if scenario == "galle":
        gdir = os.path.join(scenario_dir, "galle_scenario")
        sumo_cmd += ["--fcd-output",   os.path.join(gdir, "galle_fcd_traci.xml"),
                     "--netstate-dump", os.path.join(gdir, "galle_netstate_traci.xml")]
    traci.start(sumo_cmd)

    vehicle_speeds = {}
    step = 0

    os.makedirs(os.path.dirname(SPEED_LOG_PATH), exist_ok=True)
    with open(SPEED_LOG_PATH, 'w', newline='') as speed_f, \
         open(POSITION_LOG_PATH, 'w', newline='') as pos_f:

        speed_writer   = csv.writer(speed_f)
        pos_writer     = csv.writer(pos_f)
        speed_writer.writerow(["step", "time_s", "vehicle_id", "speed_mps", "speed_kmh"])
        pos_writer.writerow(  ["step", "time_s", "vehicle_id", "x", "y", "angle"])

        while (traci.simulation.getMinExpectedNumber() > 0
               and step < max_steps):
            traci.simulationStep()
            sim_time = traci.simulation.getTime()

            for vid in traci.vehicle.getIDList():
                speed = traci.vehicle.getSpeed(vid)           # m/s
                x, y  = traci.vehicle.getPosition(vid)
                angle = traci.vehicle.getAngle(vid)

                vehicle_speeds[vid] = speed
                speed_writer.writerow([step, sim_time, vid,
                                       round(speed, 3),
                                       round(speed * 3.6, 2)])
                pos_writer.writerow(  [step, sim_time, vid,
                                       round(x, 2), round(y, 2),
                                       round(angle, 2)])

            step += 1

    traci.close()
    print(f"[SUMO-NS3] Simulation done: {step} steps, "
          f"{len(vehicle_speeds)} unique vehicles")
    return vehicle_speeds


def _generate_dummy_speeds(scenario: str) -> dict:
    """
    Fallback: generate synthetic vehicle speed data when SUMO is unavailable.
    Used for testing MATD (Eq. 3.17) without SUMO installation.
    """
    import random
    random.seed(42)
    speeds = {}
    n_vehicles = 10 if scenario == "highway" else 6

    for i in range(n_vehicles):
        # Highway: higher speeds (80–120 km/h); urban: lower (20–50 km/h)
        if scenario == "highway":
            speed_kmh = random.uniform(80, 120)
        else:
            speed_kmh = random.uniform(20, 50)
        speeds[f"veh{i}"] = speed_kmh / 3.6  # convert to m/s

    os.makedirs(os.path.dirname(SPEED_LOG_PATH), exist_ok=True)
    with open(SPEED_LOG_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["step", "time_s", "vehicle_id", "speed_mps", "speed_kmh"])
        for vid, spd in speeds.items():
            writer.writerow([0, 0.0, vid, round(spd, 3), round(spd * 3.6, 2)])

    print(f"[SUMO-NS3] Dummy speeds generated for {len(speeds)} vehicles "
          f"({scenario} scenario)")
    return speeds


def read_ns3_speed_for_node(node_index: int,
                             speed_log: str = SPEED_LOG_PATH) -> float:
    """
    Read vehicle speed for a given NS-3 node index from the SUMO speed log.
    Maps SUMO vehicle ID 'veh{i}' → NS-3 node index i.
    Used by MATD (Eq. 3.4, 3.17) to get realistic si(t).
    """
    target_vid = f"veh{node_index}"
    try:
        with open(speed_log, 'r') as f:
            reader = csv.DictReader(f)
            last_speed = 14.0  # default 50 km/h if not found
            for row in reader:
                if row['vehicle_id'] == target_vid:
                    last_speed = float(row['speed_mps'])
            return last_speed
    except FileNotFoundError:
        return 14.0  # default m/s


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "highway"
    print(f"[SUMO-NS3] Starting {scenario} scenario bridge...")
    speeds = run_sumo_ns3_simulation(scenario)
    print("\nFinal vehicle speeds (m/s):")
    for vid, spd in sorted(speeds.items()):
        print(f"  {vid}: {spd:.2f} m/s ({spd * 3.6:.1f} km/h)")
