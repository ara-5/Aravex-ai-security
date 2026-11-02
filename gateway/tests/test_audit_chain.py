"""The tamper-evident audit trail: what it catches, and, deliberately, what it does not.

The "does not" tests are here so the documented limits are facts, not hopes: a plain chain can be
rewritten from scratch, and cutting entries off the end passes unless the head is anchored elsewhere.
"""
from __future__ import annotations

import json
import threading

import pytest
from fastapi.testclient import TestClient

from gateway.audit.chain import GENESIS, AuditChain, _hash, main, verify
from gateway.main import app
from tests.conftest import approver_headers, auth_headers

KEY = b"audit-key-for-tests"


def build(path, n=5, key=None):
    chain = AuditChain(path, key)
    for i in range(n):
        chain.append({"event": "decision", "n": i, "decision": "ALLOW" if i % 2 else "DENY"})
    return chain


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def write(path, ls):
    path.write_text("\n".join(ls) + "\n", encoding="utf-8")


def rewrite_whole_chain(path, edit, key=None):
    """What an attacker with write access to the file does: change an entry, then recompute every
    later hash so the chain looks intact. Returns the forged lines."""
    out, prev = [], GENESIS
    for ln in lines(path):
        e = json.loads(ln)
        e["record"] = edit(e["seq"], e["record"])
        body = {k: e[k] for k in ("seq", "ts", "record")} | {"prev": prev}
        e["prev"], e["hash"] = prev, _hash(body)
        if key:
            e["mac"] = "0" * 64  # the attacker does not have the key
        out.append(json.dumps(e, separators=(",", ":")))
        prev = e["hash"]
    return out


# -- what it catches -----------------------------------------------------------------------------------
def test_an_untouched_chain_verifies(tmp_path):
    p = tmp_path / "a.chain"
    chain = build(p)
    result = verify(p)
    assert result.ok and result.entries == 5 and result.head == chain.head


def test_editing_a_record_is_detected_at_that_entry(tmp_path):
    p = tmp_path / "a.chain"
    build(p)
    ls = lines(p)
    ls[2] = ls[2].replace('"DENY"', '"ALLOW"')
    write(p, ls)
    result = verify(p)
    assert not result.ok and result.at == 3 and "altered" in result.problem


def test_deleting_or_reordering_entries_in_the_middle_is_detected(tmp_path):
    p = tmp_path / "a.chain"
    build(p)
    original = lines(p)
    write(p, original[:2] + original[3:])
    assert not verify(p).ok
    swapped = original[:]
    swapped[1], swapped[2] = swapped[2], swapped[1]
    write(p, swapped)
    assert not verify(p).ok


def test_inserting_a_forged_entry_is_detected(tmp_path):
    p = tmp_path / "a.chain"
    build(p)
    ls = lines(p)
    fake = json.loads(ls[1])
    fake["record"] = {"event": "decision", "decision": "ALLOW", "note": "inserted"}
    ls.insert(2, json.dumps(fake))
    write(p, ls)
    assert not verify(p).ok


def _forge_last(path, **changes):
    """Change the last entry and recompute its own hash so ONLY the changed link is wrong."""
    ls = lines(path)
    e = json.loads(ls[-1])
    e.update(changes)
    e["hash"] = _hash({k: e[k] for k in ("seq", "ts", "record", "prev")})
    write(path, ls[:-1] + [json.dumps(e, separators=(",", ":"))])


def test_a_wrong_sequence_number_alone_is_detected(tmp_path):
    p = tmp_path / "a.chain"
    build(p, 4)
    _forge_last(p, seq=9)
    result = verify(p)
    assert not result.ok and "sequence" in result.problem


def test_a_wrong_link_to_the_previous_entry_alone_is_detected(tmp_path):
    p = tmp_path / "a.chain"
    build(p, 4)
    _forge_last(p, prev="f" * 64)
    result = verify(p)
    assert not result.ok and "follow" in result.problem


@pytest.mark.parametrize("damage", ["garbage line", "", "{}", '{"seq": 1}'])
def test_a_damaged_file_is_reported_not_raised(tmp_path, damage):
    p = tmp_path / "a.chain"
    build(p, 3)
    write(p, lines(p)[:1] + [damage])
    assert not verify(p).ok


def test_a_missing_file_is_reported(tmp_path):
    assert not verify(tmp_path / "nope").ok


def test_a_new_writer_continues_the_same_chain(tmp_path):
    p = tmp_path / "a.chain"
    build(p, 3)
    AuditChain(p).append({"event": "later"})
    assert verify(p).entries == 4 and verify(p).ok


def test_concurrent_writers_in_one_process_keep_the_chain_intact(tmp_path):
    p = tmp_path / "a.chain"
    chain = AuditChain(p)
    threads = [threading.Thread(target=lambda i=i: [chain.append({"t": i, "k": k}) for k in range(15)]) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    result = verify(p)
    assert result.ok and result.entries == 90


# -- the key: what stops a rewrite --------------------------------------------------------------------
def test_with_a_key_a_forged_chain_is_rejected(tmp_path):
    p = tmp_path / "a.chain"
    build(p, key=KEY)
    assert verify(p, KEY).ok
    forged = tmp_path / "forged.chain"
    write(forged, rewrite_whole_chain(p, lambda seq, r: {**r, "decision": "ALLOW"} if seq == 3 else r, key=KEY))
    result = verify(forged, KEY)
    assert not result.ok and "key" in result.problem


def test_verifying_with_the_wrong_key_fails(tmp_path):
    p = tmp_path / "a.chain"
    build(p, key=KEY)
    assert not verify(p, b"another-key").ok


def test_a_keyed_chain_checked_without_the_key_still_checks_the_links(tmp_path):
    p = tmp_path / "a.chain"
    build(p, key=KEY)
    ls = lines(p)
    ls[1] = ls[1].replace('"n":1', '"n":9')
    write(p, ls)
    assert not verify(p).ok


# -- the documented limits, as facts ------------------------------------------------------------------
def test_limit_without_a_key_the_whole_chain_can_be_rewritten_and_still_verifies(tmp_path):
    p = tmp_path / "a.chain"
    chain = build(p)
    anchored_head = chain.head
    forged = tmp_path / "forged.chain"
    write(forged, rewrite_whole_chain(p, lambda seq, r: {**r, "decision": "ALLOW"} if seq == 3 else r))
    assert verify(forged).ok, "this is the limit: with no key and no anchor, a full rewrite is undetectable"
    # The external anchor is what catches it.
    result = verify(forged, expect_head=anchored_head)
    assert not result.ok and "head" in result.problem


def test_limit_cutting_entries_off_the_end_passes_unless_the_head_or_count_is_anchored(tmp_path):
    p = tmp_path / "a.chain"
    chain = build(p, 6, key=KEY)
    head, count = chain.head, 6
    write(p, lines(p)[:4])
    assert verify(p, KEY).ok, "this is the limit: a shorter chain is still a valid chain"
    assert not verify(p, KEY, expect_head=head).ok
    assert not verify(p, KEY, expect_entries=count).ok


# -- the command line -----------------------------------------------------------------------------------
def test_command_line_verify_exit_codes(tmp_path, monkeypatch, capsys):
    p = tmp_path / "a.chain"
    chain = build(p, 3, key=KEY)
    monkeypatch.setenv("AUDIT_CHAIN_KEY", KEY.decode())
    assert main(["verify", str(p), "--expect-head", chain.head]) == 0
    assert main(["verify", str(p), "--expect-head", "f" * 64]) == 1
    monkeypatch.setenv("AUDIT_CHAIN_KEY", "wrong")
    assert main(["verify", str(p)]) == 1


# -- through the gateway -----------------------------------------------------------------------------
client = TestClient(app)


def test_gateway_decisions_and_approvals_land_in_the_chain(tmp_path, monkeypatch, approver_configured):
    p = tmp_path / "gateway.chain"
    monkeypatch.setenv("AUDIT_CHAIN_PATH", str(p))
    monkeypatch.setenv("AUDIT_CHAIN_KEY", KEY.decode())

    denied = client.post("/v1/agent-action", headers=auth_headers("customer-support-agent"), json={
        "human_id": "h-jane-owner", "agent_id": "customer-support-agent", "tool_id": "customer_db_tool",
        "action": "read", "resource": "secrets.api_key"}).json()
    pending = client.post("/v1/agent-action", headers=auth_headers("data-ops-agent"), json={
        "human_id": "h-jane-owner", "agent_id": "data-ops-agent", "tool_id": "database_admin_tool",
        "action": "delete", "resource": "database.chain_test", "data_classification": "HIGHLY_SENSITIVE"}).json()
    client.post(f"/v1/approvals/{pending['approval_id']}/decision", headers=approver_headers("jane"), json={"approved": True})

    assert verify(p, KEY).ok
    entries = [json.loads(ln)["record"] for ln in lines(p)]
    assert [e["event"] for e in entries] == ["decision", "decision", "approval_resolved"]
    assert entries[0]["request_id"] == denied["request_id"] and entries[0]["decision"] == "DENY"
    assert entries[2]["approver"] == "jane" and entries[2]["approved"] is True


def test_without_the_setting_nothing_is_written(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDIT_CHAIN_PATH", raising=False)
    client.post("/v1/agent-action", headers=auth_headers("customer-support-agent"), json={
        "human_id": "h-jane-owner", "agent_id": "customer-support-agent", "tool_id": "customer_db_tool",
        "action": "read", "resource": "customer_db.profile"})
    assert list(tmp_path.iterdir()) == []
