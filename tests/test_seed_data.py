from __future__ import annotations

import ssl

import pytest

from scripts import seed_data


def test_build_events_is_deterministic_and_complete() -> None:
    first = seed_data.build_events(1_800_000_000.0)
    second = seed_data.build_events(1_800_000_000.0)
    assert first == second
    assert len(first) == 1976
    assert first == sorted(first, key=lambda event: event["time"])

    ids = [event["event"]["event_id"] for event in first]
    assert len(ids) == len(set(ids))
    assert {event["event"]["dataset"] for event in first} == {seed_data.DATASET}


def test_attack_chain_is_ordered() -> None:
    events = seed_data.build_events(1_800_000_000.0)
    by_id = {event["event"]["event_id"]: event for event in events}
    assert by_id["brute-force-0179"]["time"] < by_id["initial-access"]["time"]
    assert by_id["initial-access"]["time"] < by_id["privilege-escalation"]["time"]
    assert by_id["privilege-escalation"]["time"] < by_id["lateral-movement"]["time"]
    assert by_id["lateral-movement"]["time"] < by_id["collection-staging"]["time"]
    assert by_id["collection-staging"]["time"] < by_id["exfiltration-00"]["time"]


def test_local_hec_defaults_to_scoped_unverified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_VERIFY_TLS", raising=False)
    context = seed_data.tls_context("https://localhost:8088/services/collector/event")
    assert context is not None
    assert context.verify_mode == ssl.CERT_NONE


def test_remote_hec_defaults_to_verified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_VERIFY_TLS", raising=False)
    context = seed_data.tls_context("https://splunk.example.com/services/collector/event")
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_invalid_hec_url_is_rejected() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        seed_data.tls_context("ftp://localhost/events")
