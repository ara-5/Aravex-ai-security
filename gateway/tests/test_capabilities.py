"""Capabilities: authority that can be handed down but only ever shrinks.

The properties that matter: a token cannot be altered, widened, stripped of a restriction or
forged; narrowing needs no key; and a capability can never allow what the policy denies.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from gateway import capabilities as cap
from gateway.capabilities import CapabilityError, attenuate, mint, verify
from gateway.main import app
from tests.conftest import auth_headers

ROOT = b"root-key-for-tests-0123456789abcdef"
NOW = 1_800_000_000.0
FUTURE = NOW + 3600
CTX = {"agent_id": "a1", "tool_id": "filesystem_tool", "action": "read",
       "resource": "filesystem.reports/q3.txt", "record_count": 1, "destination": "internal"}


def c(kind, value):
    return {"kind": kind, "value": value}


def token(*caveats):
    return mint(ROOT, identifier="t1", caveats=[c("expires", FUTURE), *caveats])


def ok(tok, **override):
    return verify(ROOT, tok, {**CTX, **override}, now=NOW)


def forge(tok, **changes):
    """Rewrite a token's fields WITHOUT being able to re-sign it."""
    data = cap.decode(tok)
    data.update(changes)
    return cap._encode(data)


# -- the restrictions themselves ---------------------------------------------------------------------
def test_a_token_that_covers_the_request_is_accepted():
    tok = token(c("agent_id", "a1"), c("tools", ["filesystem_tool"]), c("actions", ["read"]),
                c("resource_prefixes", ["filesystem.reports/"]), c("max_record_count", 5), c("destinations", ["internal"]))
    assert ok(tok).ok


@pytest.mark.parametrize("caveat,override,fragment", [
    (c("agent_id", "a1"), {"agent_id": "a2"}, "different agent"),
    (c("tools", ["email_tool"]), {}, "does not cover tool"),
    (c("actions", ["write"]), {}, "does not cover action"),
    (c("resource_prefixes", ["filesystem.other/"]), {}, "does not cover this resource"),
    (c("max_record_count", 0), {"record_count": 1}, "at most 0 records"),
    (c("destinations", ["external_api"]), {}, "does not cover destination"),
])
def test_each_restriction_is_enforced(caveat, override, fragment):
    verdict = ok(token(caveat), **override)
    assert not verdict.ok and fragment in verdict.reason


def test_an_expired_token_is_refused():
    assert not verify(ROOT, token(), CTX, now=FUTURE + 1).ok
    assert "expired" in verify(ROOT, token(), CTX, now=FUTURE + 1).reason


def test_a_prefix_cannot_be_escaped_with_dot_dot():
    tok = token(c("resource_prefixes", ["filesystem.reports/"]))
    assert not ok(tok, resource="filesystem.reports/../secrets/keys").ok
    assert ok(tok, resource="filesystem.reports/q3.txt").ok


# -- narrowing ---------------------------------------------------------------------------------------
def test_anyone_can_narrow_a_token_without_the_key_and_the_gateway_honours_it():
    parent = token(c("tools", ["filesystem_tool", "email_tool"]))
    child = attenuate(parent, c("tools", ["email_tool"]))
    assert ok(parent).ok, "the parent still covers the tool"
    # Positive control: a narrowed token is VALID and works for what it still covers. Without this,
    # a narrowing that produced a broken token would look the same as one that restricted correctly.
    assert ok(child, tool_id="email_tool").ok
    refused = ok(child)
    assert not refused.ok and "does not cover tool" in refused.reason, "the child dropped filesystem_tool"
    grandchild = attenuate(child, c("actions", ["send"]))
    assert ok(grandchild, tool_id="email_tool", action="send").ok
    refused = ok(grandchild, tool_id="email_tool", action="read")
    assert not refused.ok and "does not cover action" in refused.reason


def test_narrowing_never_widens_even_when_a_wider_value_is_added():
    narrow = token(c("tools", ["email_tool"]))
    still_narrow = attenuate(narrow, c("tools", ["email_tool", "filesystem_tool", "secrets_tool"]))
    assert ok(still_narrow, tool_id="email_tool").ok
    for tool in ("filesystem_tool", "secrets_tool"):
        refused = ok(still_narrow, tool_id=tool)
        assert not refused.ok and "does not cover tool" in refused.reason, "the narrow restriction still wins"


# -- tampering and forging ---------------------------------------------------------------------------
def test_removing_a_restriction_invalidates_the_token():
    tok = token(c("tools", ["email_tool"]))
    stripped = forge(tok, caveats=[x for x in cap.decode(tok)["caveats"] if x["kind"] != "tools"])
    assert not ok(stripped, tool_id="filesystem_tool").ok
    assert "signature" in ok(stripped).reason


def test_changing_a_restriction_invalidates_the_token():
    tok = token(c("tools", ["email_tool"]))
    changed = forge(tok, caveats=[c("expires", FUTURE), c("tools", ["filesystem_tool"])])
    assert "signature" in ok(changed).reason


def test_adding_a_restriction_without_resigning_or_reordering_invalidates_it():
    tok = token(c("tools", ["email_tool"]), c("actions", ["read"]))
    data = cap.decode(tok)
    assert "signature" in ok(forge(tok, caveats=data["caveats"] + [c("actions", ["read"])])).reason
    assert "signature" in ok(forge(tok, caveats=list(reversed(data["caveats"])))).reason


def test_a_token_from_another_key_or_with_a_different_id_is_refused():
    other = mint(b"some-other-root-key-0123456789", identifier="t1", caveats=[c("expires", FUTURE)])
    assert "signature" in ok(other).reason
    assert "signature" in ok(forge(token(), id="t2")).reason


def test_a_token_cannot_be_given_an_eternal_life_by_dropping_the_expiry():
    with pytest.raises(CapabilityError):
        mint(ROOT, identifier="t", caveats=[c("tools", ["x"])])
    # And a validly signed token without an expiry (made by someone holding the key) is still refused.
    sig = cap._mac(ROOT, b"t")
    sig = cap._mac(sig, cap._canon(c("tools", ["x"])))
    bare = cap._encode({"id": "t", "caveats": [c("tools", ["x"])], "sig": sig.hex()})
    assert "no expiry" in ok(bare).reason


@pytest.mark.parametrize("bad", ["", "not a token", "e30", "a" * 9000, None, 42])
def test_garbage_is_refused_without_raising(bad):
    assert not verify(ROOT, bad, CTX, now=NOW).ok


def test_an_unknown_restriction_kind_is_a_failure_not_ignored():
    sig = cap._mac(ROOT, b"t")
    for caveat in (c("expires", FUTURE), c("quantum_clearance", "yes")):
        sig = cap._mac(sig, cap._canon(caveat))
    odd = cap._encode({"id": "t", "caveats": [c("expires", FUTURE), c("quantum_clearance", "yes")], "sig": sig.hex()})
    assert not ok(odd).ok


@pytest.mark.parametrize("caveat", [
    c("tools", []), c("tools", "email_tool"), c("tools", [""]), c("expires", True), c("expires", -1),
    c("max_record_count", -1), c("max_record_count", True), c("agent_id", ""), {"kind": "tools"}, "tools",
    c("tools", ["x"] * 65),
])
def test_malformed_restrictions_are_rejected_when_added(caveat):
    with pytest.raises(CapabilityError):
        attenuate(token(), caveat)


def test_a_short_root_key_is_refused():
    with pytest.raises(CapabilityError):
        mint(b"short", identifier="t", caveats=[c("expires", FUTURE)])
    assert not verify(b"short", token(), CTX, now=NOW).ok


def test_the_number_of_restrictions_is_capped():
    tok = token()
    with pytest.raises(CapabilityError):
        for _ in range(cap.MAX_CAVEATS + 1):
            tok = attenuate(tok, c("actions", ["read"]))


# -- through the gateway ---------------------------------------------------------------------------
client = TestClient(app)
ACTION = {"human_id": "h-jane-owner", "agent_id": "customer-support-agent", "tool_id": "customer_db_tool",
          "action": "read", "resource": "customer_db.profile"}


@pytest.fixture(autouse=True)
def fresh_anomaly_state(monkeypatch):
    """Refused capabilities count as denials in the anomaly tracker (on purpose), so each test
    gets its own tracker instead of inheriting the previous test's denials."""
    import gateway.main as gm
    from gateway.policy.engine import PolicyEngine, load_rules
    from gateway.security.anomaly import AnomalyTracker
    tracker = AnomalyTracker()
    monkeypatch.setattr(gm, "anomaly_tracker", tracker)
    monkeypatch.setattr(gm, "engine", PolicyEngine(rules=load_rules(), anomaly_tracker=tracker))


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("GATEWAY_CAPABILITY_ROOT_KEY", ROOT.decode())
    monkeypatch.delenv("GATEWAY_REQUIRE_CAPABILITY", raising=False)


def post(action=None, tok=None, agent="customer-support-agent"):
    headers = auth_headers(agent)
    if tok is not None:
        headers["X-Aravex-Capability"] = tok
    return client.post("/v1/agent-action", headers=headers, json={**ACTION, **(action or {})}).json()


def live(*caveats):
    return mint(ROOT, identifier="http", caveats=[c("expires", time.time() + 600), *caveats])


def test_without_a_capability_nothing_changes(keyed):
    assert post()["decision"] == "ALLOW"


def test_a_valid_capability_allows_what_policy_allows(keyed):
    assert post(tok=live(c("agent_id", "customer-support-agent"), c("tools", ["customer_db_tool"])))["decision"] == "ALLOW"


def test_a_capability_that_does_not_cover_the_call_denies_it_and_says_so(keyed):
    d = post(tok=live(c("tools", ["email_tool"])))
    assert d["decision"] == "DENY" and d["matched_rules"] == ["capability"]
    assert "capability refused" in d["reasons"][0]


def test_a_delegated_narrower_token_limits_what_the_sub_agent_can_do(keyed):
    parent = live(c("agent_id", "customer-support-agent"))
    child = attenuate(parent, c("actions", ["read"]))
    assert post(tok=parent)["decision"] == "ALLOW"
    assert post(tok=child)["decision"] == "ALLOW", "the narrowed token still covers a read"
    send = post({"tool_id": "email_tool", "action": "send", "resource": "email.bob@example.com"}, tok=child)
    assert send["decision"] == "DENY" and "does not cover action" in send["reasons"][0]
    # The same send is fine for the parent, so the refusal came from the narrowing.
    assert post({"tool_id": "email_tool", "action": "send", "resource": "email.bob@example.com"}, tok=parent)["decision"] == "ALLOW"


def test_a_capability_can_never_grant_what_policy_denies(keyed):
    # The most permissive token possible still cannot read secrets: the base rule decides.
    d = post({"tool_id": "customer_db_tool", "resource": "secrets.api_key"}, tok=live())
    assert d["decision"] == "DENY" and "deny_secret_access" in d["matched_rules"]


@pytest.mark.parametrize("make", [
    lambda: live()[:-4] + "AAAA",                                     # altered
    lambda: mint(b"another-root-key-0123456789", identifier="x", caveats=[c("expires", time.time() + 600)]),
    lambda: mint(ROOT, identifier="x", caveats=[c("expires", time.time() - 5)]),   # already expired
    lambda: "garbage",
])
def test_bad_tokens_are_denied_at_the_gateway(keyed, make):
    d = post(tok=make())
    assert d["decision"] == "DENY" and d["matched_rules"] == ["capability"]


def test_a_token_for_another_agent_is_denied(keyed):
    assert post(tok=live(c("agent_id", "data-ops-agent")))["decision"] == "DENY"


def test_a_capability_with_no_root_key_configured_fails_closed(monkeypatch):
    monkeypatch.delenv("GATEWAY_CAPABILITY_ROOT_KEY", raising=False)
    d = post(tok=mint(ROOT, identifier="x", caveats=[c("expires", time.time() + 600)]))
    assert d["decision"] == "DENY" and "not configured" in d["reasons"][0]


def test_when_required_a_call_without_a_capability_is_denied(keyed, monkeypatch):
    monkeypatch.setenv("GATEWAY_REQUIRE_CAPABILITY", "1")
    assert post()["decision"] == "DENY"
    assert post(tok=live())["decision"] == "ALLOW"
