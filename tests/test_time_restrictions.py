import unittest
from datetime import datetime, time, date, timedelta, timezone
from zoneinfo import ZoneInfo

from rampflow.timeutil import Window, wall_window, wall_time_active
from rampflow.operational_policy import (
    PolicyRule, PolicyContext, PolicyEngine, Effect,
)
from rampflow.notam import Notam, Recurrence, NotamRegistry

UTC = timezone.utc
SH = "Asia/Shanghai"
LDN = "Europe/London"
NYC = "America/New_York"


def at(zone, y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=ZoneInfo(zone))


class OvernightPolicyTests(unittest.TestCase):
    def setUp(self):
        self.ban = PolicyRule(
            "NIGHT", 10, frozenset({"move"}), Effect.DENY, "night ban",
            start_local=time(22, 0), end_local=time(2, 0), zone=SH,
        )
        self.engine = PolicyEngine([self.ban])

    def allowed(self, dt):
        return self.engine.evaluate(
            PolicyContext("move", "F", "PVG", "T1", dt, {})
        ).allowed

    def test_evening_before_ban_is_allowed(self):
        self.assertTrue(self.allowed(at(SH, 2026, 1, 5, 21, 59)))

    def test_ban_starts_at_evening_boundary(self):
        self.assertFalse(self.allowed(at(SH, 2026, 1, 5, 22, 0)))

    def test_post_midnight_segment_is_enforced(self):
        # Regression: the 00:00-02:00 portion used to leak because matching was
        # done as a same-day UTC wall-clock comparison.
        self.assertFalse(self.allowed(at(SH, 2026, 1, 6, 0, 30)))
        self.assertFalse(self.allowed(at(SH, 2026, 1, 6, 1, 59)))

    def test_half_open_end_releases_exactly_at_2am(self):
        self.assertTrue(self.allowed(at(SH, 2026, 1, 6, 2, 0)))

    def test_local_zone_is_used_not_utc(self):
        # 22:00 Shanghai is 14:00 UTC; a UTC-only comparison would release it.
        ctx_at = datetime(2026, 1, 5, 14, 0, tzinfo=UTC)
        self.assertFalse(
            self.engine.evaluate(
                PolicyContext("move", "F", "PVG", "T1", ctx_at, {})
            ).allowed
        )

    def test_weekday_attribution_of_post_midnight_segment(self):
        rule = PolicyRule(
            "MON", 10, frozenset({"move"}), Effect.DENY, "monday night",
            start_local=time(22), end_local=time(2), zone=SH,
            weekdays=frozenset({0}),  # Monday
        )
        engine = PolicyEngine([rule])
        # Tuesday 01:00 local belongs to Monday's night band.
        denied = engine.evaluate(
            PolicyContext("move", "F", "PVG", "T1", at(SH, 2026, 1, 6, 1), {})
        )
        # Tuesday 23:00 is Tuesday evening; no Monday band covers it.
        released = engine.evaluate(
            PolicyContext("move", "F", "PVG", "T1", at(SH, 2026, 1, 6, 23), {})
        )
        self.assertFalse(denied.allowed)
        self.assertTrue(released.allowed)


class PolicyRevisionTests(unittest.TestCase):
    def _rule(self, rid="R"):
        return PolicyRule(rid, 10, frozenset({"push"}), Effect.DENY, "x")

    def test_decisions_carry_revision(self):
        engine = PolicyEngine([self._rule()])
        decision = engine.evaluate(
            PolicyContext("push", "F", "A", "T", at("UTC", 2026, 1, 1, 12), {})
        )
        self.assertEqual(decision.revision, 1)
        self.assertEqual(engine.explain(
            PolicyContext("push", "F", "A", "T", at("UTC", 2026, 1, 1, 12), {})
        )["revision"], 1)

    def test_add_remove_replace_bump_revision(self):
        engine = PolicyEngine()
        self.assertEqual(engine.revision, 0)
        engine.add(self._rule())
        self.assertTrue(engine.remove("R"))
        self.assertEqual(engine.revision, 2)
        self.assertFalse(engine.remove("R"))
        self.assertEqual(engine.revision, 2)
        self.assertEqual(engine.replace_rules([self._rule("S")]), 3)

    def test_failed_replace_is_atomic(self):
        engine = PolicyEngine([self._rule()])
        with self.assertRaises(ValueError):
            engine.replace_rules([self._rule("A"), self._rule("A")])
        self.assertEqual(set(engine.rules), {"R"})
        self.assertEqual(engine.revision, 1)

    def test_invalid_weekdays_rejected(self):
        with self.assertRaises(ValueError):
            PolicyRule("R", 1, frozenset(), Effect.DENY, "x", weekdays=frozenset())
        with self.assertRaises(ValueError):
            PolicyRule("R", 1, frozenset(), Effect.DENY, "x", weekdays=frozenset({7}))

    def test_partial_local_window_rejected(self):
        with self.assertRaises(ValueError):
            PolicyRule("R", 1, frozenset(), Effect.DENY, "x",
                       start_local=time(22))


class OvernightRecurrenceTests(unittest.TestCase):
    def setUp(self):
        self.effective = Window(
            datetime(2026, 1, 1, tzinfo=UTC),
            datetime(2026, 1, 10, tzinfo=UTC),
        )

    def _registry(self, start, end, weekdays=frozenset(range(7))):
        rec = Recurrence(weekdays, start, end, SH)
        notam = Notam("N1", "apron", "vehicles", self.effective, 5,
                      "closed", recurrence=rec)
        return NotamRegistry([notam])

    def test_post_midnight_part_not_cut_at_day_rollover(self):
        reg = self._registry(time(22), time(2))
        horizon = Window(
            datetime(2026, 1, 4, tzinfo=UTC),
            datetime(2026, 1, 8, tzinfo=UTC),
        )
        effects = reg.effects("apron", "vehicles", horizon)
        self.assertTrue(effects)
        # Nightly bands touch at local midnight and are merged: the first band
        # starts Jan 4 22:00 SH (14:00Z), the last ends Jan 8 02:00 SH (Jan 7
        # 18:00Z). Nothing is sliced off at the date boundary.
        self.assertEqual(effects[0].window.start,
                         datetime(2026, 1, 4, 14, 0, tzinfo=UTC))
        self.assertEqual(effects[-1].window.end,
                         datetime(2026, 1, 7, 18, 0, tzinfo=UTC))

    def test_decision_holds_during_post_midnight_segment(self):
        reg = self._registry(time(22), time(2))
        instant = datetime(2026, 1, 5, 17, 0, tzinfo=UTC)  # Jan 6 01:00 SH
        decision = reg.decision(
            "apron", "vehicles",
            Window(instant, instant + timedelta(minutes=1)),
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.details["revision"], reg.revision)

    def test_decision_releases_after_band_end(self):
        reg = self._registry(time(22), time(2))
        instant = datetime(2026, 1, 5, 18, 0, tzinfo=UTC)  # Jan 6 02:00 SH
        decision = reg.decision(
            "apron", "vehicles",
            Window(instant, instant + timedelta(minutes=1)),
        )
        self.assertTrue(decision.accepted)

    def test_daytime_band_with_weekday_filter(self):
        reg = self._registry(time(8), time(10), weekdays=frozenset({0}))
        horizon = Window(
            datetime(2026, 1, 4, tzinfo=UTC),
            datetime(2026, 1, 8, tzinfo=UTC),
        )
        effects = reg.effects("apron", "vehicles", horizon)
        # Only Monday Jan 5: 08:00-10:00 SH == 00:00-02:00 UTC.
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0].window.start,
                         datetime(2026, 1, 5, 0, 0, tzinfo=UTC))
        self.assertEqual(effects[0].window.end,
                         datetime(2026, 1, 5, 2, 0, tzinfo=UTC))

    def test_exception_and_inclusion_dates_still_apply_overnight(self):
        rec = Recurrence(frozenset({0}), time(22), time(2), SH,
                         exception_dates=frozenset({date(2026, 1, 5)}),
                         inclusion_dates=frozenset({date(2026, 1, 6)}))
        notam = Notam("N1", "apron", "vehicles", self.effective, 5,
                      "closed", recurrence=rec)
        reg = NotamRegistry([notam])
        horizon = Window(
            datetime(2026, 1, 5, tzinfo=UTC),
            datetime(2026, 1, 8, tzinfo=UTC),
        )
        effects = reg.effects("apron", "vehicles", horizon)
        # Monday Jan 5 band removed by exception; Tuesday Jan 6 added.
        starts = {e.window.start for e in effects}
        self.assertNotIn(datetime(2026, 1, 5, 14, tzinfo=UTC), starts)
        self.assertIn(datetime(2026, 1, 6, 14, tzinfo=UTC), starts)


class SharedWallTimeSemanticsTests(unittest.TestCase):
    def test_instant_and_window_expansion_never_disagree(self):
        # Minute-by-minute cross-check across the Europe/London fall-back night
        # (clocks repeat 01:00-02:00 on 2026-10-25).
        rule_kwargs = dict(start_local=time(23), end_local=time(4),
                           zone=LDN, weekdays=frozenset({5}))
        rec = Recurrence(frozenset({5}), time(23), time(4), LDN)
        effective = Window(datetime(2026, 10, 1, tzinfo=UTC),
                           datetime(2026, 11, 1, tzinfo=UTC))
        reg = NotamRegistry([Notam("N", "a", "b", effective, 1, "closed",
                                   recurrence=rec)])
        engine = PolicyEngine([PolicyRule(
            "B", 1, frozenset({"x"}), Effect.DENY, "r", **rule_kwargs)])
        horizon = Window(datetime(2026, 10, 24, 20, tzinfo=UTC),
                         datetime(2026, 10, 25, 6, tzinfo=UTC))
        windows = [e.window for e in reg.effects("a", "b", horizon)]
        t = horizon.start
        while t < horizon.end:
            via_window = any(w.contains(t) for w in windows)
            via_instant = not engine.evaluate(
                PolicyContext("x", "f", "LHR", "T", t, {})
            ).allowed
            self.assertIs(via_window, via_instant, t)
            t += timedelta(minutes=1)

    def test_repeated_hour_denied_under_both_folds(self):
        # 01:45 BST (00:45Z) and 01:45 GMT (01:45Z) both fall in 23:00-04:00.
        for instant in (datetime(2026, 10, 25, 0, 45, tzinfo=UTC),
                        datetime(2026, 10, 25, 1, 45, tzinfo=UTC)):
            self.assertTrue(wall_time_active(instant, time(23), time(4), LDN))
        # 04:00 GMT sharp is the half-open end.
        self.assertFalse(wall_time_active(
            datetime(2026, 10, 25, 4, 0, tzinfo=UTC), time(23), time(4), LDN))

    def test_fall_back_full_day_covers_twenty_five_hours(self):
        band = wall_window(date(2026, 10, 25), time(0), time(0), LDN)
        self.assertEqual(band.minutes, 25 * 60)

    def test_spring_forward_band_covers_skipped_hour(self):
        # New York jumps 02:00 EST -> 03:00 EDT on 2026-03-08. A 01:00-03:00
        # band spans the gap (06:00Z-07:00Z) rather than collapsing on it.
        band = wall_window(date(2026, 3, 8), time(1), time(3), NYC)
        self.assertEqual(band.start, datetime(2026, 3, 8, 6, tzinfo=UTC))
        self.assertEqual(band.end, datetime(2026, 3, 8, 7, tzinfo=UTC))
        self.assertTrue(wall_time_active(
            datetime(2026, 3, 8, 6, 30, tzinfo=UTC), time(1), time(3), NYC))


if __name__ == "__main__":
    unittest.main()
