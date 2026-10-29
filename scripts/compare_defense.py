"""Run the same red-team campaign against the target agent twice, once bare
and once behind the Aravex gateway, and report the difference per category.

    python scripts/compare_defense.py [--out report.md] [--workers 1]

It starts everything itself (gateway, target, red-team CLI) on local ports,
uses throwaway databases, and cleans up. Needs the dependencies of both
redteam/requirements.txt and gateway/requirements.txt in the current
environment.

A finding is a technique whose attack succeeded. "Mitigated" means it
succeeded unprotected and not when protected; the gateway-addressable column
says where a gateway *can* help, so a category the gateway cannot reach is
not counted against it.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "schemas"))
from aravex_schemas import CATEGORY_LAYER  # noqa: E402

GATEWAY_PORT, TARGET_PORT = 8000, 8001
AGENT_ID = "nova-assistant"


def wait_for(url: str, proc: subprocess.Popen, name: str, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{name} exited early (code {proc.returncode})")
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"{name} did not become healthy at {url}")


def mint_key(agent_id: str = AGENT_ID, rotate: bool = True) -> str:
    """Return the dev bearer key for ``agent_id``. ``rotate=False`` reuses existing keys,
    so a gateway restarted later still accepts keys handed out earlier."""
    keys_file = ROOT / "gateway" / ".secrets" / "agent_keys.dev.yaml"
    if rotate or not keys_file.exists() or agent_id not in (yaml.safe_load(keys_file.read_text()) or {}).get("agents", {}):
        subprocess.run([sys.executable, "scripts/generate_agent_keys.py"], cwd=ROOT / "gateway",
                       check=True, capture_output=True)
    return yaml.safe_load(keys_file.read_text())["agents"][agent_id]


def run_campaign(mode: str, tmp: Path, gateway_key: str, workers: int) -> dict[str, dict]:
    env = {**os.environ,
           "TARGET_PORT": str(TARGET_PORT),
           "TARGET_DATABASE_URL": f"sqlite:///{(tmp / f'target_{mode}.db').as_posix()}",
           "REDTEAM_DATABASE_URL": f"sqlite:///{(tmp / f'redteam_{mode}.db').as_posix()}",
           "TARGET_AGENT_URL": f"http://127.0.0.1:{TARGET_PORT}",
           "GATEWAY_MODE": mode, "GATEWAY_URL": f"http://127.0.0.1:{GATEWAY_PORT}",
           "GATEWAY_AGENT_ID": AGENT_ID, "GATEWAY_API_KEY": gateway_key}
    target = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "target_agent.main:app", "--port", str(TARGET_PORT), "--log-level", "warning"],
        cwd=ROOT / "redteam", env=env)
    try:
        wait_for(f"http://127.0.0.1:{TARGET_PORT}/health", target, "target agent")
        subprocess.run([sys.executable, "-m", "redteam_engine.cli", "campaign", "run",
                        "--name", f"compare-{mode}", "--workers", str(workers)],
                       cwd=ROOT / "redteam", env=env, check=True, capture_output=True)
    finally:
        target.terminate()
        target.wait(timeout=15)

    con = sqlite3.connect(tmp / f"redteam_{mode}.db")
    try:
        attempted = dict(con.execute("SELECT category, COUNT(DISTINCT technique) FROM attack_attempts GROUP BY category"))
        succeeded = dict(con.execute("SELECT category, COUNT(DISTINCT technique) FROM findings GROUP BY category"))
    finally:
        con.close()
    return {c: {"attempted": attempted[c], "succeeded": succeeded.get(c, 0)} for c in attempted}


def render(bare: dict, guarded: dict) -> str:
    lines = ["# Aravex: attack success with and without the gateway", "",
             "| Category | Gateway can address | Techniques tried | Succeeded (bare) | Succeeded (gateway) | Mitigated |",
             "|---|---|---:|---:|---:|---:|"]
    tot_b = tot_g = 0
    for cat in sorted(set(bare) | set(guarded)):
        b = bare.get(cat, {}).get("succeeded", 0)
        g = guarded.get(cat, {}).get("succeeded", 0)
        n = bare.get(cat, {}).get("attempted", guarded.get(cat, {}).get("attempted", 0))
        layer = CATEGORY_LAYER.get(cat)
        lines.append(f"| {cat} | {layer.value if layer else 'unclassified'} | {n} | {b} | {g} | {max(b - g, 0)} |")
        tot_b, tot_g = tot_b + b, tot_g + g
    lines += ["", f"**Total:** {tot_b} successful attacks bare, {tot_g} behind the gateway.", "",
              "Counts are distinct techniques whose attack succeeded. The gateway's rate-based anomaly "
              "detector is disabled for this run so the numbers reflect policy, not request volume.", "",
              "'Gateway can address' is a design classification (see `schemas/aravex_schemas/coverage.py`), "
              "not a result. Remaining successes in `gateway` categories are policy gaps to close; "
              "successes in `model` categories need model-level defenses."]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="write the markdown report here")
    ap.add_argument("--workers", type=int, default=1)
    args = ap.parse_args()

    key = mint_key()
    gateway = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "gateway.main:app", "--port", str(GATEWAY_PORT), "--log-level", "warning"],
        cwd=ROOT / "gateway", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        # A campaign sends hundreds of calls a minute; without this the
        # anomaly detector blocks on volume and hides how the policy itself does.
        env={**os.environ, "ANOMALY_RATE_THRESHOLD": "1000000", "ANOMALY_FAIL_THRESHOLD": "1000000"})
    try:
        wait_for(f"http://127.0.0.1:{GATEWAY_PORT}/healthz", gateway, "gateway")
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            print("Campaign 1/2: target without gateway...", flush=True)
            bare = run_campaign("off", tmp, key, args.workers)
            print("Campaign 2/2: target behind gateway...", flush=True)
            guarded = run_campaign("enforce", tmp, key, args.workers)
    finally:
        gateway.terminate()
        gateway.wait(timeout=15)

    report = render(bare, guarded)
    print(report)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
