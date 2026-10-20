"""Schedule labelling and leakage-safe split planning (purge gap, day splits, short classes)."""

from datetime import UTC, datetime

import pytest

from ml.dataset import BENIGN, DEFAULT_SCHEDULE, label_flow, load_schedule
from ml.splits import PURGE, TEST, TRAIN, VAL, ClassWindow, build_split_plan

ACTIVE = 120.0
GAP = 2 * ACTIVE


# ---------------------------------------------------------------- schedule / labelling


def test_default_schedule_has_published_classes_and_epoch_conversion():
    windows = load_schedule()
    classes = {w.cls for w in windows}
    assert {
        "FTP-Patator",
        "SSH-Patator",
        "DoS-Hulk",
        "Heartbleed",
        "PortScan",
        "DDoS",
        "Botnet",
        "Infiltration",
    } <= classes
    ftp = next(w for w in windows if w.cls == "FTP-Patator")
    # 2017-07-04 09:20 local, UTC-3 -> 12:20 UTC
    assert ftp.start_ts == datetime(2017, 7, 4, 12, 20, tzinfo=UTC).timestamp()
    assert ftp.end_ts - ftp.start_ts == 3600
    shifted = next(w for w in load_schedule(DEFAULT_SCHEDULE, utc_offset_hours=0) if w.cls == "FTP-Patator")
    assert shifted.start_ts == datetime(2017, 7, 4, 9, 20, tzinfo=UTC).timestamp()


def test_label_flow_uses_pair_direction_nat_alias_and_time():
    windows = load_schedule()
    inside = datetime(2017, 7, 4, 12, 30, tzinfo=UTC).timestamp()
    outside = datetime(2017, 7, 4, 20, 0, tzinfo=UTC).timestamp()
    assert label_flow(windows, "205.174.165.73", "192.168.10.50", inside) == "FTP-Patator"
    assert label_flow(windows, "192.168.10.50", "205.174.165.73", inside) == "FTP-Patator"  # reverse direction
    assert label_flow(windows, "172.16.0.1", "192.168.10.50", inside) == "FTP-Patator"  # NAT alias
    assert label_flow(windows, "172.16.0.1", "192.168.10.50", outside) == BENIGN
    assert label_flow(windows, "172.16.0.1", "192.168.10.99", inside) == BENIGN  # not the victim
    assert label_flow(windows, "10.9.9.9", "192.168.10.50", inside) == BENIGN  # not the attacker


def test_label_flow_supports_cidr_victims_without_nat_alias():
    windows = load_schedule()
    t = datetime(2017, 7, 6, 18, 30, tzinfo=UTC).timestamp()  # 15:30 local, Infiltration step 2
    assert label_flow(windows, "192.168.10.8", "192.168.10.77", t) == "Infiltration"
    assert label_flow(windows, "172.16.0.1", "192.168.10.77", t) == BENIGN


# ---------------------------------------------------------------- splitting


def _flows(span, step=10.0, dur=5.0):
    t = span[0]
    while t < span[1]:
        yield t, min(t + dur, span[1])
        t += step


def _plan(windows, spans, **kw):
    return build_split_plan(windows, spans, active_timeout=ACTIVE, **kw)


def test_purge_gap_is_twice_active_timeout():
    plan = _plan([], {"d": (0.0, 1000.0)})
    assert plan.purge_gap == 240.0
    assert build_split_plan([], {"d": (0.0, 1000.0)}, active_timeout=60.0).purge_gap == 120.0


def test_time_blocks_are_ordered_and_separated_by_at_least_the_purge_gap():
    spans = {"d": (0.0, 20000.0)}
    plan = _plan([ClassWindow("A", "d", 2000.0, 8000.0)], spans)
    assert plan.class_policy["A"] == "time_blocks"
    kept = {TRAIN: [], VAL: [], TEST: []}
    for s, e in _flows((2000.0, 8000.0)):
        sp = plan.split_of("d", s, e)
        if sp:
            kept[sp].append((s, e))
    assert all(kept[k] for k in kept)
    assert max(e for _, e in kept[TRAIN]) < min(s for s, _ in kept[VAL])
    assert max(e for _, e in kept[VAL]) < min(s for s, _ in kept[TEST])
    assert min(s for s, _ in kept[VAL]) - max(e for _, e in kept[TRAIN]) >= GAP - 10.0  # grid step tolerance
    assert min(s for s, _ in kept[TEST]) - max(e for _, e in kept[VAL]) >= GAP - 10.0


def test_no_flow_can_span_two_splits():
    spans = {"d": (0.0, 20000.0)}
    plan = _plan([ClassWindow("A", "d", 2000.0, 8000.0)], spans)
    tl = plan.timelines["d"]
    boundaries = [tl[i][0] for i in range(1, len(tl)) if tl[i][2] != tl[i - 1][2]]
    assert boundaries
    for b in boundaries:
        # a flow starting shortly before a boundary and lasting active_timeout crosses it -> must be dropped
        assert plan.split_of("d", b - 30.0, b + ACTIVE) is None
    for start in range(0, 20000, 7):
        sp = plan.split_of("d", float(start), start + ACTIVE)
        if sp is not None:
            # every interval the flow touches belongs to that same split
            touched = {iv[2] for iv in plan.timelines["d"] if iv[0] < start + ACTIVE and iv[1] > start}
            assert touched == {sp}


def test_purged_zone_flows_are_dropped():
    plan = _plan([ClassWindow("A", "d", 2000.0, 8000.0)], {"d": (0.0, 20000.0)})
    purges = [(a, b) for a, b, sp in plan.timelines["d"] if sp == PURGE]
    assert purges
    a, b = purges[0]
    assert plan.split_of("d", a + 1.0, a + 2.0) is None


def test_short_single_day_class_is_zero_shot_test_by_default_or_train_by_policy():
    spans = {"d": (0.0, 20000.0)}
    win = [ClassWindow("S", "d", 10000.0, 10300.0)]
    plan = _plan(win, spans)
    assert plan.class_policy["S"] == "short_test"
    assert plan.split_of("d", 10100.0, 10105.0) == TEST
    assert _plan(win, spans, short_class_policy="train").split_of("d", 10100.0, 10105.0) == TRAIN


def test_class_on_multiple_days_is_split_by_day():
    spans = {"d1": (0.0, 10000.0), "d2": (20000.0, 30000.0), "d3": (40000.0, 50000.0)}
    two = _plan([ClassWindow("M", "d1", 1000.0, 2000.0), ClassWindow("M", "d2", 21000.0, 22000.0)], spans)
    assert two.class_policy["M"] == "by_day"
    assert two.split_of("d1", 1200.0, 1210.0) == TRAIN
    assert two.split_of("d2", 21200.0, 21210.0) == TEST
    three = _plan(
        [ClassWindow("M", f, a, a + 1000.0) for f, a in (("d1", 1000.0), ("d2", 21000.0), ("d3", 41000.0))], spans
    )
    assert [three.split_of(f, a + 200.0, a + 210.0) for f, a in (("d1", 1000.0), ("d2", 21000.0), ("d3", 41000.0))] == [
        TRAIN,
        VAL,
        TEST,
    ]


def test_background_traffic_is_split_chronologically_with_gaps():
    plan = _plan([], {"d": (0.0, 10000.0)})
    assert plan.split_of("d", 100.0, 105.0) == TRAIN
    assert plan.split_of("d", 6500.0, 6505.0) == VAL
    assert plan.split_of("d", 9500.0, 9505.0) == TEST
    assert plan.split_of("d", 4990.0, 5100.0) is None  # straddles train/val boundary


def test_segments_cover_exactly_the_test_intervals():
    plan = _plan([ClassWindow("A", "d", 2000.0, 8000.0)], {"d": (0.0, 20000.0)})
    segs = plan.segments(TEST)
    assert segs and all(f == "d" and b > a for f, a, b in segs)
    for f, a, b in segs:
        assert plan.split_of(f, a + 1.0, a + 2.0) in (TEST, None)  # None only inside a purge head
        assert plan.split_of(f, b - 2.0, b - 1.0) == TEST


def test_invalid_arguments_rejected():
    with pytest.raises(ValueError):
        build_split_plan([], {"d": (0.0, 1.0)}, short_class_policy="drop")
    with pytest.raises(ValueError):
        build_split_plan([], {"d": (0.0, 1.0)}, fractions=(0.5, 0.5, 0.5))
