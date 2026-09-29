"""A small async load test against a running gateway.

Fires a realistic mix of request types (mostly cheap reads that ALLOW, a
handful of DENYs and HUMAN_APPROVALs) at a configurable concurrency and
reports latency percentiles and throughput. Not a substitute for a proper
load-testing tool (Locust, k6) on a real deployment -- this is here so the
project has a real, reproducible performance number instead of an assumed
one, and so `scripts/record_demo_gif.py` has a traffic source to point a
screen capture at.

Run:
    python scripts/generate_agent_keys.py   # once
    uvicorn gateway.main:app --reload       # or docker compose up
    python scripts/loadtest.py --requests 300 --concurrency 20
"""
from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from agent.demo_agent import load_dev_key

BASE_URL = "http://127.0.0.1:8000"

# Weighted mix of scenarios -- mostly routine reads, a realistic sprinkling
# of things that get denied or escalated, matching the shape of traffic a
# real customer-support agent fleet would actually generate.
SCENARIOS = [
    # (weight, agent_id, tool_id, action, resource, extra_fields)
    (70, "customer-support-agent", "customer_db_tool", "read", "customer_db.profile", {}),
    (15, "customer-support-agent", "email_tool", "send", "email.send", {}),
    (8, "customer-support-agent", "customer_db_tool", "read", "secrets.api_key",
     {"data_classification": "HIGHLY_SENSITIVE"}),
    (5, "customer-support-agent", "customer_db_tool", "export", "customer_db.bulk",
     {"record_count": 5000, "data_classification": "SENSITIVE", "destination": "external_api"}),
    (2, "data-ops-agent", "database_admin_tool", "delete", "database.production_orders",
     {"data_classification": "HIGHLY_SENSITIVE"}),
]


def pick_scenario() -> tuple[str, str, str, str, dict]:
    total = sum(s[0] for s in SCENARIOS)
    r = random.uniform(0, total)
    upto = 0.0
    for weight, agent_id, tool_id, action, resource, extra in SCENARIOS:
        upto += weight
        if r <= upto:
            return agent_id, tool_id, action, resource, extra
    return SCENARIOS[0][1:5] + ({},)  # pragma: no cover -- float rounding fallback


async def fire_one(client: httpx.AsyncClient, keys: dict[str, str]) -> tuple[float, int]:
    agent_id, tool_id, action, resource, extra = pick_scenario()
    body = {
        "human_id": "h-jane-owner",
        "agent_id": agent_id,
        "tool_id": tool_id,
        "action": action,
        "resource": resource,
        **extra,
    }
    headers = {"Authorization": f"Bearer {keys[agent_id]}"}
    start = time.perf_counter()
    response = await client.post("/v1/agent-action", json=body, headers=headers)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return elapsed_ms, response.status_code


async def run(total_requests: int, concurrency: int) -> None:
    keys = {
        agent_id: load_dev_key(agent_id)
        for agent_id in ("customer-support-agent", "data-ops-agent", "billing-agent")
    }
    if not all(keys.values()):
        raise SystemExit("Missing agent credentials -- run scripts/generate_agent_keys.py first.")

    latencies: list[float] = []
    status_counts: dict[int, int] = {}
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:

        async def worker() -> None:
            async with semaphore:
                elapsed_ms, status = await fire_one(client, keys)
                latencies.append(elapsed_ms)
                status_counts[status] = status_counts.get(status, 0) + 1

        start = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(total_requests)))
        wall_seconds = time.perf_counter() - start

    latencies.sort()

    def pct(p: float) -> float:
        idx = min(len(latencies) - 1, int(len(latencies) * p))
        return latencies[idx]

    print(f"AegisAI gateway load test -- {total_requests} requests, concurrency {concurrency}")
    print("-" * 60)
    print(f"Wall time:        {wall_seconds:.2f}s")
    print(f"Throughput:       {total_requests / wall_seconds:.1f} req/s")
    print(f"Latency p50:      {pct(0.50):.1f} ms")
    print(f"Latency p95:      {pct(0.95):.1f} ms")
    print(f"Latency p99:      {pct(0.99):.1f} ms")
    print(f"Latency max:      {max(latencies):.1f} ms")
    print(f"Latency mean:     {statistics.mean(latencies):.1f} ms")
    print(f"Status codes:     {dict(sorted(status_counts.items()))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    asyncio.run(run(args.requests, args.concurrency))
