"""Bio-inspired adaptive latency tests.

Assert the documented immune-response behaviour: persistent/aggressive sessions
get progressively slower drips, bounded by max_multiplier.
"""

from eventhorizon.adaptive import AdaptiveLatency, AdaptiveState


def test_fresh_session_is_near_baseline():
    adaptive = AdaptiveLatency(max_multiplier=8.0)
    fresh = AdaptiveState()
    mult = adaptive.multiplier(fresh)
    assert 1.0 <= mult <= 1.5  # essentially baseline for a brand-new session


def test_persistence_increases_latency_monotonically():
    adaptive = AdaptiveLatency(max_multiplier=8.0)
    light = AdaptiveState(interactions=1, bytes_seen=10, age_seconds=1.0)
    heavy = AdaptiveState(interactions=40, bytes_seen=40000, age_seconds=90.0)
    assert adaptive.multiplier(heavy) > adaptive.multiplier(light)
    assert adaptive.multiplier(light) >= 1.0


def test_multiplier_is_bounded_by_max():
    adaptive = AdaptiveLatency(max_multiplier=8.0)
    insane = AdaptiveState(interactions=10_000, bytes_seen=10_000_000, age_seconds=10_000)
    mult = adaptive.multiplier(insane)
    assert 1.0 <= mult <= 8.0


def test_delay_for_scales_base_delay():
    adaptive = AdaptiveLatency(max_multiplier=8.0)
    heavy = AdaptiveState(interactions=40, bytes_seen=40000, age_seconds=90.0)
    base = 0.05
    delay = adaptive.delay_for(base, heavy)
    assert delay > base
    assert delay <= base * 8.0 + 1e-9


def test_disabled_adaptive_is_constant():
    adaptive = AdaptiveLatency(enabled=False, max_multiplier=8.0)
    heavy = AdaptiveState(interactions=1000, bytes_seen=999999, age_seconds=999)
    assert adaptive.multiplier(heavy) == 1.0
    assert adaptive.delay_for(0.05, heavy) == 0.05


def test_observe_accumulates_signals():
    st = AdaptiveState()
    st.observe(nbytes=100, interaction=True, age=5.0)
    st.observe(nbytes=50, interaction=True, age=10.0)
    assert st.bytes_seen == 150
    assert st.interactions == 2
    assert st.age_seconds == 10.0
