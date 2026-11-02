"""A tamper-evident audit trail: every entry commits to the one before it.

Each line records {seq, ts, record, prev, hash} where hash = SHA-256 over the rest and prev is
the previous entry's hash. Edit a record, delete or reorder lines in the middle, and the chain no
longer verifies, and `verify` says where it first breaks.

What this does and does not protect (read this before relying on it):

  * Plain chain: detects accidental damage and clumsy tampering. Someone who can write the file
    can still rewrite the WHOLE chain with fresh hashes, so it proves little on its own.
  * With a key (AUDIT_CHAIN_KEY, held by the gateway and not by whoever stores the log): every
    entry also carries an HMAC. An attacker without the key cannot forge or splice entries.
  * Neither detects the newest entries being cut off the end. For that, record the head hash
    (or the entry count) somewhere the log's writer cannot reach, and pass it to
    `verify --expect-head` / `--expect-entries`.
  * One process writes the chain. Two gateways appending to one file would fork it.

Opt in with AUDIT_CHAIN_PATH. Once it is set, a write failure fails the request (the audit
comes before the answer), because evidence-grade audit that silently drops entries is worse
than an outage.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")


def _hash(body: dict) -> str:
    return hashlib.sha256(_canon(body)).hexdigest()


def _mac(key: bytes, digest: str) -> str:
    return hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ChainResult:
    ok: bool
    entries: int
    head: str
    problem: str = ""
    at: int | None = None  # sequence number where verification first failed

    def __str__(self) -> str:
        if self.ok:
            return f"chain OK: {self.entries} entries, head {self.head}"
        where = f" at entry {self.at}" if self.at is not None else ""
        return f"chain BROKEN{where}: {self.problem}"


class AuditChain:
    def __init__(self, path: str | Path, key: bytes | None = None):
        self.path = Path(path)
        self.key = key or None
        self._lock = threading.Lock()
        self._seq, self._head = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()][-1]
        entry = json.loads(last)
        return int(entry["seq"]), str(entry["hash"])

    @property
    def head(self) -> str:
        return self._head

    def append(self, record: dict) -> dict:
        with self._lock:
            body = {"seq": self._seq + 1, "ts": datetime.now(timezone.utc).isoformat(),
                    "record": record, "prev": self._head}
            entry = {**body, "hash": _hash(body)}
            if self.key:
                entry["mac"] = _mac(self.key, entry["hash"])
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=True, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq, self._head = entry["seq"], entry["hash"]
            return entry


def verify(path: str | Path, key: bytes | None = None, *, expect_head: str | None = None,
           expect_entries: int | None = None) -> ChainResult:
    """Walk the file and check every link. Never raises on a damaged file."""
    p = Path(path)
    if not p.exists():
        return ChainResult(False, 0, GENESIS, "the log file does not exist")
    prev, seq = GENESIS, 0
    for number, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            return ChainResult(False, seq, prev, f"line {number} is blank", seq + 1)
        try:
            entry = json.loads(line)
            body = {k: entry[k] for k in ("seq", "ts", "record", "prev")}
            claimed = entry["hash"]
        except Exception:
            return ChainResult(False, seq, prev, f"line {number} is not a valid entry", seq + 1)
        if entry["seq"] != seq + 1:
            return ChainResult(False, seq, prev, f"sequence jumps from {seq} to {entry['seq']} (entries removed or reordered)", entry["seq"])
        if entry["prev"] != prev:
            return ChainResult(False, seq, prev, "entry does not follow the one before it (entries removed or reordered)", entry["seq"])
        if _hash(body) != claimed:
            return ChainResult(False, seq, prev, "entry content was altered", entry["seq"])
        if key and not hmac.compare_digest(str(entry.get("mac", "")), _mac(key, claimed)):
            return ChainResult(False, seq, prev, "entry was not written by the holder of the key", entry["seq"])
        prev, seq = claimed, entry["seq"]
    if expect_entries is not None and seq != expect_entries:
        return ChainResult(False, seq, prev, f"expected {expect_entries} entries but found {seq} (entries cut off the end?)", None)
    if expect_head is not None and prev != expect_head:
        return ChainResult(False, seq, prev, "the head does not match the expected head (entries cut off the end, or rewritten)", None)
    return ChainResult(True, seq, prev)


# -- wiring for the gateway --------------------------------------------------------------------------
_chains: dict[tuple[str, bytes | None], AuditChain] = {}
_chains_lock = threading.Lock()


def configured() -> AuditChain | None:
    path = os.environ.get("AUDIT_CHAIN_PATH")
    if not path:
        return None
    key = os.environ.get("AUDIT_CHAIN_KEY", "").encode("utf-8") or None
    with _chains_lock:
        ident = (path, key)
        if ident not in _chains:
            _chains[ident] = AuditChain(path, key)
        return _chains[ident]


def record(event: str, **fields) -> None:
    chain = configured()
    if chain is not None:
        chain.append({"event": event, **fields})


# -- command line ------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m gateway.audit.chain", description="Verify a tamper-evident audit log.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check every link in the chain")
    v.add_argument("path")
    v.add_argument("--key-env", default="AUDIT_CHAIN_KEY", help="environment variable holding the HMAC key, if one was used")
    v.add_argument("--expect-head", help="head hash recorded somewhere safe; catches entries cut off the end")
    v.add_argument("--expect-entries", type=int, help="entry count recorded somewhere safe")
    args = p.parse_args(argv)
    key = os.environ.get(args.key_env, "").encode("utf-8") or None
    result = verify(args.path, key, expect_head=args.expect_head, expect_entries=args.expect_entries)
    print(result)
    if result.ok and not key:
        print("note: no key was used, so someone who could edit the file could have rewritten the whole chain", file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
