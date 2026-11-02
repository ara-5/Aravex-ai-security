"""Capabilities: delegable authority that can only shrink.

A human (or the platform) mints a token for an agent. That agent can hand a NARROWER
token to a sub-agent, and the sub-agent to another, without asking the gateway and without
holding the root key. Nobody in the chain can widen what they were given or forge a token.

How it works (the macaroon construction): the token carries a list of restrictions
("caveats") and a signature. The signature starts as HMAC(root_key, identifier) and each
caveat re-signs it: sig = HMAC(previous_sig, caveat). Anyone can append a caveat and
re-sign, because they hold the previous signature. Nobody can remove one, because that
needs the signature from before it, and nobody can change one for the same reason. Only the
gateway, which holds the root key, can recompute the chain and check it.

A capability can only RESTRICT. It is checked on top of the normal policy, never instead of
it, so a token can never allow something the policy would deny.

Safety choices:
  * every token must carry an expiry;
  * an unknown restriction kind is a failure, not ignored;
  * resource restrictions are plain prefixes, not regexes, because the party adding a
    restriction is untrusted and a pathological regex would stall the gateway;
  * a resource containing '..' never satisfies a prefix restriction (no path escape);
  * tokens and restriction lists are size-limited.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass

MAX_TOKEN_CHARS = 8192
MAX_CAVEATS = 32
MAX_LIST = 64
MAX_ITEM = 200
MIN_KEY_BYTES = 16

LIST_KINDS = {"tools", "actions", "resource_prefixes", "destinations"}
KINDS = LIST_KINDS | {"agent_id", "expires", "max_record_count"}


class CapabilityError(ValueError):
    """The token or caveat is malformed."""


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str = ""


# -- encoding ---------------------------------------------------------------------------------------
def _canon(caveat: dict) -> bytes:
    return json.dumps(caveat, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _encode(token: dict) -> str:
    raw = json.dumps(token, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(token: str) -> dict:
    """Parse a token WITHOUT checking its signature. For inspection and attenuation only."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
        raise CapabilityError("token is missing or too large")
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        data = json.loads(raw.decode("utf-8"))
        ident, caveats, sig = data["id"], data["caveats"], data["sig"]
        bytes.fromhex(sig)
    except Exception as exc:
        raise CapabilityError("token is not a valid capability") from exc
    if not isinstance(ident, str) or not ident or not isinstance(caveats, list) or len(caveats) > MAX_CAVEATS:
        raise CapabilityError("token is not a valid capability")
    for c in caveats:
        check_caveat(c)
    return {"id": ident, "caveats": caveats, "sig": sig}


def check_caveat(c: object) -> None:
    if not isinstance(c, dict) or set(c) != {"kind", "value"} or c["kind"] not in KINDS:
        raise CapabilityError(f"unknown or malformed restriction: {str(c)[:80]}")
    kind, value = c["kind"], c["value"]
    if kind in LIST_KINDS:
        if not isinstance(value, list) or not value or len(value) > MAX_LIST or not all(
                isinstance(v, str) and v and len(v) <= MAX_ITEM for v in value):
            raise CapabilityError(f"'{kind}' must be a short list of non-empty strings")
    elif kind == "agent_id":
        if not isinstance(value, str) or not value or len(value) > MAX_ITEM:
            raise CapabilityError("'agent_id' must be a non-empty string")
    elif kind == "expires":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise CapabilityError("'expires' must be a positive timestamp")
    elif kind == "max_record_count":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CapabilityError("'max_record_count' must be a non-negative integer")


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
        raise CapabilityError(f"the root key must be at least {MIN_KEY_BYTES} bytes")


# -- issuing and narrowing ------------------------------------------------------------------------------
def mint(root_key: bytes, *, identifier: str, caveats: list[dict]) -> str:
    """Issue a token. Needs the root key, so only the platform can do this."""
    _check_key(root_key)
    if not isinstance(identifier, str) or not identifier:
        raise CapabilityError("a token needs an identifier")
    if len(caveats) > MAX_CAVEATS:
        raise CapabilityError("too many restrictions")
    for c in caveats:
        check_caveat(c)
    if not any(c["kind"] == "expires" for c in caveats):
        raise CapabilityError("a token must carry an expiry")
    sig = _mac(root_key, identifier.encode("utf-8"))
    for c in caveats:
        sig = _mac(sig, _canon(c))
    return _encode({"id": identifier, "caveats": caveats, "sig": sig.hex()})


def attenuate(token: str, caveat: dict) -> str:
    """Add a restriction. Needs no key. The result is never more powerful than the input."""
    data = decode(token)
    check_caveat(caveat)
    if len(data["caveats"]) >= MAX_CAVEATS:
        raise CapabilityError("too many restrictions")
    sig = _mac(bytes.fromhex(data["sig"]), _canon(caveat))
    out = _encode({"id": data["id"], "caveats": data["caveats"] + [caveat], "sig": sig.hex()})
    if len(out) > MAX_TOKEN_CHARS:
        raise CapabilityError("token would become too large")
    return out


# -- checking -----------------------------------------------------------------------------------------
def verify(root_key: bytes, token: str, context: dict, *, now: float | None = None) -> Verdict:
    """Check a token against one request. context: agent_id, tool_id, action, resource,
    record_count, destination. Every restriction must hold. Fails closed on anything odd."""
    if not isinstance(root_key, bytes) or len(root_key) < MIN_KEY_BYTES:
        return Verdict(False, "capability verification is not configured")
    try:
        data = decode(token)
    except CapabilityError:
        return Verdict(False, "malformed capability")

    sig = _mac(root_key, data["id"].encode("utf-8"))
    for c in data["caveats"]:
        sig = _mac(sig, _canon(c))
    if not hmac.compare_digest(sig.hex(), data["sig"]):
        return Verdict(False, "capability signature is invalid (altered, or not issued by this gateway)")
    if not any(c["kind"] == "expires" for c in data["caveats"]):
        return Verdict(False, "capability has no expiry")

    t = time.time() if now is None else now
    for c in data["caveats"]:
        kind, value = c["kind"], c["value"]
        if kind == "expires":
            if t > value:
                return Verdict(False, "capability has expired")
        elif kind == "agent_id":
            if context.get("agent_id") != value:
                return Verdict(False, f"capability was issued to a different agent than '{context.get('agent_id')}'")
        elif kind == "tools":
            if context.get("tool_id") not in value:
                return Verdict(False, f"capability does not cover tool '{context.get('tool_id')}'")
        elif kind == "actions":
            if context.get("action") not in value:
                return Verdict(False, f"capability does not cover action '{context.get('action')}'")
        elif kind == "destinations":
            if context.get("destination") not in value:
                return Verdict(False, f"capability does not cover destination '{context.get('destination')}'")
        elif kind == "max_record_count":
            if int(context.get("record_count", 0)) > value:
                return Verdict(False, f"capability allows at most {value} records")
        elif kind == "resource_prefixes":
            resource = str(context.get("resource", ""))
            if ".." in resource or not any(resource.startswith(p) for p in value):
                return Verdict(False, "capability does not cover this resource")
    return Verdict(True)


# -- command line ---------------------------------------------------------------------------------------
def _restrictions(args: argparse.Namespace, now: float) -> list[dict]:
    out: list[dict] = []
    if getattr(args, "agent", None):
        out.append({"kind": "agent_id", "value": args.agent})
    for kind, raw in (("tools", args.tools), ("actions", args.actions),
                      ("resource_prefixes", args.prefix), ("destinations", args.destinations)):
        if raw:
            out.append({"kind": kind, "value": [x for x in raw.split(",") if x]})
    if args.max_records is not None:
        out.append({"kind": "max_record_count", "value": args.max_records})
    if args.ttl is not None:
        out.append({"kind": "expires", "value": int(now + args.ttl)})
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m gateway.capabilities",
                                description="Mint, narrow and inspect capability tokens.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def narrowing(sp, agent: bool):
        if agent:
            sp.add_argument("--agent", required=True, help="the only agent_id this token is good for")
        sp.add_argument("--tools", help="comma-separated tool ids")
        sp.add_argument("--actions", help="comma-separated actions (read, write, send, ...)")
        sp.add_argument("--prefix", help="comma-separated resource prefixes, e.g. filesystem.reports/")
        sp.add_argument("--destinations", help="comma-separated destinations, e.g. internal")
        sp.add_argument("--max-records", type=int)
        sp.add_argument("--ttl", type=int, help="seconds from now until the token expires")

    m = sub.add_parser("mint", help="issue a token (needs the root key)")
    m.add_argument("--id", required=True, help="identifier for this token, for the audit trail")
    m.add_argument("--key-env", default="GATEWAY_CAPABILITY_ROOT_KEY", help="environment variable holding the root key")
    narrowing(m, agent=True)
    a = sub.add_parser("attenuate", help="narrow a token (needs no key)")
    a.add_argument("token")
    narrowing(a, agent=False)
    i = sub.add_parser("inspect", help="show a token's restrictions (does NOT check the signature)")
    i.add_argument("token")
    args = p.parse_args(argv)

    now = time.time()
    try:
        if args.cmd == "inspect":
            data = decode(args.token)
            print(json.dumps({"id": data["id"], "caveats": data["caveats"],
                              "note": "signature not checked; only the gateway can do that"}, indent=2))
            return 0
        restrictions = _restrictions(args, now)
        if args.cmd == "mint":
            key = os.environ.get(args.key_env, "").encode("utf-8")
            print(mint(key, identifier=args.id, caveats=restrictions))
            return 0
        token = args.token
        if not restrictions:
            raise CapabilityError("give at least one restriction to add")
        for r in restrictions:
            token = attenuate(token, r)
        print(token)
        return 0
    except CapabilityError as exc:
        print(f"capabilities: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
