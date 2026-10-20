"""
Leakage-safe train/validation/test splitting for flow datasets. Never random rows.

Rules:
  * A class whose attack windows fall on more than one capture file is split by file (day):
    first -> train, last -> test, the middle one(s) -> validation (two days: train/test, no class validation).
  * A class on a single file is split by contiguous time blocks (train | purge | val | purge | test) laid over
    the concatenation of its windows. Every block boundary is followed by a purge gap of at least
    2 x active_timeout, so no flow can span two splits.
  * A single-file class too short to give both validation and test blocks longer than the purge gap cannot be
    split: by default it is held out entirely as test (zero-shot); policy "train" puts it in train instead.
  * Everything outside attack windows (background traffic) is split chronologically per file by the same
    fractions, again with purge gaps at every change of split.
  * A flow is kept only if its whole [start, end] lies inside one non-purge interval of one split.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

TRAIN, VAL, TEST, PURGE = "train", "val", "test", "purge"
SPLITS = (TRAIN, VAL, TEST)

Interval = tuple[float, float, str]


@dataclass(frozen=True)
class ClassWindow:
    cls: str
    file: str
    start_ts: float
    end_ts: float


def _overlay(timeline: list[Interval], start: float, end: float, split: str) -> list[Interval]:
    if end <= start:
        return timeline
    out: list[Interval] = []
    for a, b, sp in timeline:
        if b <= start or a >= end:
            out.append((a, b, sp))
            continue
        if a < start:
            out.append((a, start, sp))
        if b > end:
            out.append((end, b, sp))
    out.append((start, end, split))
    out.sort()
    return out


def _insert_purges(timeline: list[Interval], gap: float) -> list[Interval]:
    """
    At every change of split, carve `gap` seconds out as PURGE. The gap is taken from the longer of the two
    neighbours so a short block (for example a 2-minute attack window) is not consumed by its own purge.
    """
    out: list[list[float | str]] = []
    for a, b, sp in timeline:
        if out and out[-1][2] != sp and PURGE not in (out[-1][2], sp):
            pa, pb, psp = float(out[-1][0]), float(out[-1][1]), out[-1][2]
            if pb - pa >= b - a:
                cut = max(pa, pb - gap)
                out.pop()
                if cut > pa:
                    out.append([pa, cut, psp])
                out.append([cut, pb, PURGE])
                out.append([a, b, sp])
            else:
                cut = min(b, a + gap)
                out.append([a, cut, PURGE])
                if cut < b:
                    out.append([cut, b, sp])
        else:
            out.append([a, b, sp])
    return [(float(a), float(b), str(sp)) for a, b, sp in out]


def _cum_pieces(windows: list[tuple[float, float]], pieces: list[tuple[float, float, str]]) -> list[Interval]:
    """Map cumulative-duration pieces back onto epoch time across (possibly disjoint) windows."""
    out: list[Interval] = []
    offset = 0.0
    for ws, we in windows:
        length = we - ws
        for ca, cb, sp in pieces:
            lo, hi = max(ca, offset), min(cb, offset + length)
            if hi > lo:
                out.append((ws + (lo - offset), ws + (hi - offset), sp))
        offset += length
    return out


@dataclass
class SplitPlan:
    timelines: dict[str, list[Interval]]
    purge_gap: float
    class_policy: dict[str, str] = field(default_factory=dict)  # class -> "time_blocks" | "by_day" | "short_test" | ...
    _starts: dict[str, list[float]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._starts = {f: [iv[0] for iv in tl] for f, tl in self.timelines.items()}

    def split_of(self, file: str, start_ts: float, end_ts: float) -> str | None:
        """Split a flow belongs to, or None if purged / spanning more than one split / file unknown."""
        tl = self.timelines.get(file)
        if not tl:
            return None
        lo, hi = tl[0][0], tl[-1][1]
        s, e = min(max(start_ts, lo), hi), min(max(end_ts, lo), hi)
        starts = self._starts[file]
        i = max(0, bisect.bisect_right(starts, s) - 1)
        seen: set[str] = set()
        while i < len(tl) and tl[i][0] <= e:
            if tl[i][1] > s or tl[i][0] == s:
                seen.add(tl[i][2])
            i += 1
        if len(seen) != 1:
            return None
        only = next(iter(seen))
        return None if only == PURGE else only

    def segments(self, split: str) -> list[tuple[str, float, float]]:
        """Merged (file, start, end) time ranges belonging to `split`."""
        out: list[tuple[str, float, float]] = []
        for file in sorted(self.timelines):
            cur: list[float] | None = None
            for a, b, sp in self.timelines[file]:
                if sp == split:
                    if cur is not None and abs(cur[1] - a) < 1e-9:
                        cur[1] = b
                    else:
                        if cur is not None:
                            out.append((file, cur[0], cur[1]))
                        cur = [a, b]
                elif cur is not None:
                    out.append((file, cur[0], cur[1]))
                    cur = None
            if cur is not None:
                out.append((file, cur[0], cur[1]))
        return out


def build_split_plan(
    windows: list[ClassWindow],
    spans: dict[str, tuple[float, float]],
    active_timeout: float = 120.0,
    fractions: tuple[float, float, float] = (0.5, 0.2, 0.3),
    short_class_policy: str = "test",
) -> SplitPlan:
    """Build per-file split timelines. `spans` maps file -> (first_ts, last_ts) of the capture."""
    if short_class_policy not in ("test", "train"):
        raise ValueError("short_class_policy must be 'test' or 'train'")
    if abs(sum(fractions) - 1.0) > 1e-9 or min(fractions) <= 0:
        raise ValueError("fractions must be positive and sum to 1")
    gap = 2.0 * active_timeout
    f_train, f_val, _ = fractions

    timelines: dict[str, list[Interval]] = {}
    for file, (t0, t1) in spans.items():
        length = t1 - t0
        c1, c2 = t0 + f_train * length, t0 + (f_train + f_val) * length
        timelines[file] = [(t0, c1, TRAIN), (c1, c2, VAL), (c2, t1, TEST)]

    by_class: dict[str, list[ClassWindow]] = defaultdict(list)
    for w in windows:
        if w.file in spans:
            lo, hi = spans[w.file]
            by_class[w.cls].append(ClassWindow(w.cls, w.file, max(w.start_ts, lo), min(w.end_ts, hi)))

    policy: dict[str, str] = {}
    by_day: dict[str, list[str]] = {}
    single: list[tuple[str, list[ClassWindow], str]] = []
    for cls in sorted(by_class):
        ws = [w for w in by_class[cls] if w.end_ts > w.start_ts]
        files = sorted({w.file for w in ws}, key=lambda f: spans[f][0])
        if len(files) > 1:
            by_day[cls] = files
            policy[cls] = "by_day"
            continue
        if not files:
            continue
        single.append((cls, ws, files[0]))
    for files in by_day.values():
        # Whole capture days go to one split: first -> train, last -> test, middle -> validation.
        day_split = {files[0]: TRAIN, files[-1]: TEST} | {f: VAL for f in files[1:-1]}
        for f, sp in day_split.items():
            timelines[f] = _overlay(timelines[f], spans[f][0], spans[f][1], sp)
    for cls, ws, file in single:
        ranges = sorted((w.start_ts, w.end_ts) for w in ws)
        total = sum(b - a for a, b in ranges)
        c1, c2 = f_train * total, (f_train + f_val) * total
        if (c2 - c1 - gap) <= 0 or (total - c2 - gap) <= 0:
            policy[cls] = f"short_{short_class_policy}"
            for a, b in ranges:
                timelines[file] = _overlay(timelines[file], a, b, short_class_policy)
            continue
        policy[cls] = "time_blocks"
        pieces = [
            (0.0, c1, TRAIN),
            (c1, c1 + gap, PURGE),
            (c1 + gap, c2, VAL),
            (c2, c2 + gap, PURGE),
            (c2 + gap, total, TEST),
        ]
        for a, b, sp in _cum_pieces(ranges, pieces):
            timelines[file] = _overlay(timelines[file], a, b, sp)

    return SplitPlan(
        timelines={f: _insert_purges(tl, gap) for f, tl in timelines.items()},
        purge_gap=gap,
        class_policy=policy,
    )
