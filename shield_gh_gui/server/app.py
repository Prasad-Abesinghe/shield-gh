"""SHIELD-GH GUI backend: real offline evidence + real (bounded) online runs.

Serves the bundled GUI HTML at / and a small JSON API under /api/. Does not
edit or write into routing.cc, shield_gh/, shield_gh_ml/, or any evidence
folder — only reads them (offline_data.py) or invokes the pre-built binary
as a subprocess (run_manager.py).
"""
import os

from flask import Flask, jsonify, request, send_from_directory

import offline_data
from run_manager import manager

GUI_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GUI_FILE = "SHIELD-GH GUI (standalone) (3).html"

app = Flask(__name__)


@app.get("/")
def index():
    return send_from_directory(GUI_DIR, GUI_FILE)


@app.get("/api/offline/datasets")
def offline_datasets():
    return jsonify(offline_data.list_datasets())


@app.get("/api/offline/data")
def offline_data_route():
    key = request.args.get("dataset", "")
    result = offline_data.read_dataset(key)
    if result is None:
        return jsonify({"error": f"dataset '{key}' not found or file missing on disk"}), 404
    return jsonify(result)


@app.post("/api/online/start")
def online_start():
    body = request.get_json(force=True, silent=True) or {}
    run, error = manager.start_run(
        attack=body.get("attack", "S1"),
        preset=body.get("preset", "demo"),
        ai_on=bool(body.get("aiOn", False)),
        n_vehicles=body.get("N"),
        sim_time=body.get("simTime"),
    )
    if error:
        return jsonify({"error": error}), 409
    return jsonify({"run_id": run.run_id, "args": run.args})


@app.get("/api/online/status")
def online_status():
    run_id = request.args.get("run_id", "")
    run = manager.get(run_id)
    if run is None:
        return jsonify({"error": f"no such run_id '{run_id}'"}), 404
    since = request.args.get("since", 0, type=int)
    status = run.status()
    status["events"] = status["events"][since:] if since else status["events"]
    return jsonify(status)


@app.post("/api/online/stop")
def online_stop():
    body = request.get_json(force=True, silent=True) or {}
    run_id = body.get("run_id", "")
    ok = manager.stop(run_id)
    if not ok:
        return jsonify({"error": f"no such run_id '{run_id}'"}), 404
    return jsonify({"stopped": True})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
