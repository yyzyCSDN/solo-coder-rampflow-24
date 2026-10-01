from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Iterable, Iterator

UTC = timezone.utc

def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone-aware datetime required")
    return value

def utc(value: datetime) -> datetime:
    return ensure_aware(value).astimezone(UTC)

def localize_wall(day: datetime, hour: int, minute: int, zone: str, fold: int = 0) -> datetime:
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise ValueError("invalid wall clock")
    z = ZoneInfo(zone)
    base = day.astimezone(z)
    return datetime(base.year, base.month, base.day, hour, minute, tzinfo=z, fold=fold)

def minutes_between(start: datetime, end: datetime) -> int:
    a, b = utc(start), utc(end)
    if b < a:
        raise ValueError("negative interval")
    return int((b-a).total_seconds()//60)

def ceil_minutes(delta: timedelta) -> int:
    sec = delta.total_seconds()
    if sec < 0:
        raise ValueError("negative duration")
    return int((sec + 59)//60)

@dataclass(frozen=True, order=True)
class Window:
    start: datetime
    end: datetime
    def __post_init__(self):
        a, b = utc(self.start), utc(self.end)
        if b <= a:
            raise ValueError("window end must be after start")
        object.__setattr__(self, "start", a)
        object.__setattr__(self, "end", b)
    @property
    def minutes(self) -> int:
        return int((self.end-self.start).total_seconds()//60)
    def overlaps(self, other: "Window", touching: bool = False) -> bool:
        if touching:
            return self.start <= other.end and other.start <= self.end
        return self.start < other.end and other.start < self.end
    def contains(self, instant: datetime, end_inclusive: bool = False) -> bool:
        t = utc(instant)
        return self.start <= t <= self.end if end_inclusive else self.start <= t < self.end
    def intersection(self, other: "Window") -> "Window | None":
        s, e = max(self.start, other.start), min(self.end, other.end)
        return Window(s,e) if s < e else None
    def shift(self, minutes: int) -> "Window":
        d = timedelta(minutes=minutes)
        return Window(self.start+d, self.end+d)
    def expand(self, before: int = 0, after: int = 0) -> "Window":
        return Window(self.start-timedelta(minutes=before), self.end+timedelta(minutes=after))

def merge_windows(windows: Iterable[Window], join_touching: bool = True) -> list[Window]:
    ordered = sorted(windows, key=lambda w: (w.start,w.end))
    out: list[Window] = []
    for item in ordered:
        if not out:
            out.append(item)
            continue
        last = out[-1]
        condition = item.start <= last.end if join_touching else item.start < last.end
        if condition:
            out[-1] = Window(last.start, max(last.end,item.end))
        else:
            out.append(item)
    return out

def subtract_windows(base: Window, blocked: Iterable[Window]) -> list[Window]:
    pieces=[base]
    for block in merge_windows([b for b in blocked if b.overlaps(base)]):
        nxt=[]
        for piece in pieces:
            inter=piece.intersection(block)
            if inter is None:
                nxt.append(piece); continue
            if piece.start < inter.start:
                nxt.append(Window(piece.start, inter.start))
            if inter.end < piece.end:
                nxt.append(Window(inter.end, piece.end))
        pieces=nxt
    return pieces

def minute_ticks(window: Window, step: int = 1) -> Iterator[datetime]:
    if step <= 0:
        raise ValueError("positive step required")
    cur=window.start
    delta=timedelta(minutes=step)
    while cur < window.end:
        yield cur
        cur += delta

# Recurring wall-clock rules (night bans, periodic notices).  The weekday of a
# rule always belongs to the day on which the rule starts; a wall end earlier
# than the wall start runs past midnight into the next day.  Ambiguous or
# missing wall times caused by DST are widened so every consumer of these
# helpers interprets the same night identically (fail towards coverage rather
# than letting one path allow and another deny).

def _wall(day: date, wall: time, z: ZoneInfo, fold: int) -> datetime:
    return datetime(day.year, day.month, day.day, wall.hour, wall.minute,
                    wall.second, wall.microsecond, tzinfo=z, fold=fold)

def local_rule_window(day: date, start: time, end: time, zone: str) -> Window:
    """One anchored occurrence of a wall-clock rule; end<=start rolls to the next day.

    Equal start/end denotes a full-day rule.  DST gaps/folds are widened: the
    earliest possible start instant and latest possible end instant are used.
    """
    z = ZoneInfo(zone)
    if start == end:
        s = _wall(day, time.min, z, 0)
        e = _wall(day + timedelta(days=1), time.min, z, 0)
        return Window(s, e)
    starts = [_wall(day, start, z, f) for f in (0, 1)]
    if end <= start:
        ends = [_wall(day + timedelta(days=1), end, z, f) for f in (0, 1)]
    else:
        ends = [_wall(day, end, z, f) for f in (0, 1)]
    candidates = [Window(s, e) for s in starts for e in ends if e > s]
    if not candidates:
        raise ValueError("invalid local rule window")
    return Window(min(w.start for w in candidates), max(w.end for w in candidates))

def local_rule_contains(day: date, start: time, end: time, zone: str, instant: datetime) -> bool:
    """Whether an aware instant falls inside the rule anchored on ``day``.

    Half-open on both ends, so an overnight rule and the following day's rule
    never disagree at the shared boundary instant.
    """
    w = local_rule_window(day, start, end, zone)
    return w.contains(utc(instant))

def local_rule_occurrences(
    horizon: Window,
    zone: str,
    start: time,
    end: time,
    weekdays: frozenset[int] | None = None,
    exception_dates: frozenset[date] = frozenset(),
    inclusion_dates: frozenset[date] = frozenset(),
    clip: Window | None = None,
) -> list[Window]:
    """All anchored rule windows overlapping ``horizon``, split at day rollover.

    Each returned window belongs to one anchor date; callers that need one
    continuous span across midnight should merge the result.  ``clip`` (e.g.
    the NOTAM overall effective window) is applied in addition to ``horizon``.
    """
    z = ZoneInfo(zone)
    first = horizon.start.astimezone(z).date() - timedelta(days=1)
    last = horizon.end.astimezone(z).date() + timedelta(days=1)
    out: list[Window] = []
    cur = first
    while cur <= last:
        active = cur in inclusion_dates or (
            (weekdays is None or cur.weekday() in weekdays) and cur not in exception_dates
        )
        if active:
            w = local_rule_window(cur, start, end, zone).intersection(horizon)
            if w is not None and clip is not None:
                w = w.intersection(clip)
            if w is not None:
                out.append(w)
        cur += timedelta(days=1)
    return out
