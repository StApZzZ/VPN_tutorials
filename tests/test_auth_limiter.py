"""FailureLimiter: per-username and per-IP budgets, bounded memory."""
import pytest

import config
from auth.deps import FailureLimiter


@pytest.fixture
def limiter(monkeypatch):
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES", 3)
    monkeypatch.setattr(config, "AUTH_MAX_FAILURES_PER_IP", 5)
    monkeypatch.setattr(config, "AUTH_FAILURE_WINDOW_SECONDS", 900)
    return FailureLimiter()


def test_username_budget_is_shared_by_all_ips(limiter):
    for n in range(3):
        limiter.failed(f"198.51.100.{n}", "Ivan")
    assert limiter.blocked("203.0.113.9", "ivan")  # usernames compare case-insensitively
    assert not limiter.blocked("203.0.113.9", "olga")


def test_ip_budget_is_shared_by_all_usernames(limiter):
    for n in range(5):
        limiter.failed("198.51.100.1", f"user{n}")
    assert limiter.blocked("198.51.100.1", "someone-new")
    assert limiter.blocked_ip("198.51.100.1") and not limiter.blocked_ip("198.51.100.2")


def test_success_restores_the_username_budget_but_not_the_ip_budget(limiter):
    for _ in range(3):
        limiter.failed("198.51.100.1", "ivan")
    limiter.failed("198.51.100.1", "olga")
    limiter.reset("198.51.100.1", "ivan")
    assert not limiter.blocked_user("ivan")
    limiter.failed("198.51.100.1", "petr")
    assert limiter.blocked_ip("198.51.100.1")  # 5 failures from it in the window


def test_expired_keys_are_dropped(limiter, monkeypatch):
    monkeypatch.setattr(config, "AUTH_FAILURE_WINDOW_SECONDS", 0)
    for n in range(50):
        limiter.failed("198.51.100.1", f"user-{n}" * 1000)
    assert not limiter.blocked("198.51.100.1", "user-1" * 1000)
    assert not limiter.blocked_ip("198.51.100.1")
    for n in range(50):
        limiter.blocked_user(f"user-{n}" * 1000)
    assert len(limiter._events) == 0


def test_key_count_is_capped_and_usernames_are_hashed(limiter, monkeypatch):
    monkeypatch.setattr(FailureLimiter, "MAX_KEYS", 10)
    for n in range(100):
        limiter.failed("198.51.100.1", f"{n}-" + "x" * 100_000)
    assert len(limiter._events) <= 10
    assert all(len(key[1]) <= 64 for key in limiter._events)


def test_lock_is_noticed_once_per_window(limiter):
    assert limiter.first_notice("198.51.100.1", "ivan")
    assert not limiter.first_notice("198.51.100.1", "ivan")
    assert limiter.first_notice("198.51.100.1", "olga")
    assert limiter.first_notice("198.51.100.2", "ivan")
