import unittest
from datetime import datetime, timezone, timedelta, date, time

from rampflow.timeutil import Window, local_rule_window, local_rule_contains
from rampflow.notam import Notam, NotamRegistry, Recurrence
from rampflow.operational_policy import PolicyRule, PolicyContext, PolicyEngine, Effect

UTC = timezone.utc
SH = "Asia/Shanghai"      # fixed UTC+8, no DST
BERLIN = "Europe/Berlin"


def utc(y, m, d, h=0, mi=0):
    return datetime(y, m, d, h, mi, tzinfo=UTC)


class NightRuleTests(unittest.TestCase):
    def setUp(self):
        # Friday-anchored night ban 22:00-06:00 local, running into Saturday.
        self.effective = Window(utc(2025, 12, 1), utc(2026, 3, 1))
        self.ban = Notam(
            "N-BAN", "rwy", "18", self.effective, 10, "prohibited",
            Recurrence(frozenset({4}), time(22, 0), time(6, 0), SH),
        )
        self.registry = NotamRegistry([self.ban])
        self.horizon = Window(utc(2026, 1, 1), utc(2026, 1, 8))

    def test_effect_spans_midnight_without_gap(self):
        effects = self.registry.effects("rwy", "18", self.horizon)
        cst = timezone(timedelta(hours=8))
        fri = next(
            e for e in effects
            if e.window.start.astimezone(cst).date() == date(2026, 1, 2)
        )
        # Friday 22:00 CST == 14:00Z, Saturday 06:00 CST == 22:00Z, one window.
        self.assertEqual(fri.window.start, utc(2026, 1, 2, 14))
        self.assertEqual(fri.window.end, utc(2026, 1, 2, 22))
        self.assertEqual(fri.window.minutes, 8 * 60)

    def test_early_morning_tail_enforced(self):
        # 03:00 Saturday CST used to leak through because the window was dropped.
        sat_early = utc(2026, 1, 2, 19)  # Sat 03:00 Shanghai
        d = self.registry.decision("rwy", "18", Window(sat_early, sat_early + timedelta(minutes=1)))
        self.assertFalse(d.accepted)

    def test_evening_and_following_midday_clear(self):
        for t in (
            utc(2026, 1, 2, 13),   # Fri 21:00, before start
            utc(2026, 1, 2, 23),   # Sat 07:00, after tail
            utc(2026, 1, 1, 19),   # Fri 03:00: anchored Thursday, not banned
            utc(2026, 1, 3, 19),   # Sun 03:00: anchored Saturday, not banned
        ):
            d = self.registry.decision("rwy", "18", Window(t, t + timedelta(minutes=1)))
            self.assertTrue(d.accepted, f"unexpected ban at {t}")

    def test_weekday_ownership_is_start_day(self):
        # Sunday 03:00 must not be charged to Sunday's (inactive) anchor;
        # it belongs to Saturday's anchor, which is inactive too here.
        self.assertTrue(local_rule_contains(
            date(2026, 1, 3), time(22), time(6), SH, utc(2026, 1, 3, 15)))  # Sun 23:00
        self.assertFalse(local_rule_contains(
            date(2026, 1, 2), time(22), time(6), SH, utc(2026, 1, 3, 15)))  # wrong anchor

    def test_periodic_notice_not_truncated_at_rollover(self):
        notice = Notam(
            "N-NOTICE", "apron", "*", self.effective, 5, "advisory",
            Recurrence(frozenset({2}), time(23, 0), time(1, 0), SH),  # Wed -> Thu
        )
        reg = NotamRegistry([notice])
        effects = reg.effects("apron", "stand", self.horizon)
        self.assertEqual(len(effects), 1)
        w = effects[0].window
        # Wed 23:00 CST = 15:00Z through Thu 01:00 CST = 17:00Z, continuous.
        self.assertEqual((w.start, w.end), (utc(2026, 1, 7, 15), utc(2026, 1, 7, 17)))
        late = utc(2026, 1, 7, 16, 30)  # Thu 00:30 local, the formerly cut part
        d = reg.decision("apron", "stand", Window(late, late + timedelta(minutes=1)))
        self.assertTrue(d.accepted)
        self.assertEqual(d.code, "conditional")

    def test_exception_and_inclusion_dates(self):
        ban = Notam(
            "N-BAN2", "rwy", "18", self.effective, 10, "prohibited",
            Recurrence(
                frozenset({4}), time(22), time(6), SH,
                exception_dates=frozenset({date(2026, 1, 2)}),  # Friday night off
                inclusion_dates=frozenset({date(2026, 1, 3)}),  # Sunday night on
            ),
        )
        reg = NotamRegistry([ban])
        effects = reg.effects("rwy", "18", self.horizon)
        starts = {e.window.start for e in effects}
        self.assertNotIn(utc(2026, 1, 2, 14), starts)   # excepted
        self.assertIn(utc(2026, 1, 3, 14), starts)      # included Sunday
        for e in effects:
            self.assertEqual(e.revision, reg.revision)

    def test_revision_tracks_upsert_and_cancel_on_effects(self):
        self.assertEqual(self.registry.revision, 0)
        rev = self.registry.upsert(self.ban)
        self.assertEqual(rev, 1)
        e = self.registry.effects("rwy", "18", self.horizon)[0]
        self.assertEqual(e.revision, 1)
        d = self.registry.decision("rwy", "18",
                                   Window(utc(2026, 1, 2, 19), utc(2026, 1, 2, 20)))
        self.assertEqual(d.details["revision"], 1)
        self.assertTrue(self.registry.cancel("N-BAN"))
        self.assertEqual(self.registry.effects("rwy", "18", self.horizon), ())


class PolicyNightRuleTests(unittest.TestCase):
    def _engine(self, **kw):
        rule = PolicyRule(
            "CURFEW", 10, frozenset({"push"}), Effect.DENY, "night curfew", **kw)
        return PolicyEngine([rule])

    def test_overnight_local_rule_in_policy_engine(self):
        eng = self._engine(start_local=time(22), end_local=time(6), zone=SH)
        def allowed(t):
            return eng.evaluate(PolicyContext("push", "F", "APT", "T", t, {})).allowed
        self.assertFalse(allowed(utc(2026, 1, 2, 19)))   # Sat 03:00 local
        self.assertFalse(allowed(utc(2026, 1, 2, 14)))   # Fri 22:00 exactly (inclusive)
        self.assertTrue(allowed(utc(2026, 1, 2, 22)))    # Sat 06:00 exactly (exclusive)
        self.assertTrue(allowed(utc(2026, 1, 2, 2)))     # Fri 10:00 local

    def test_equal_bounds_means_full_day(self):
        w = local_rule_window(date(2026, 1, 2), time(0), time(0), SH)
        self.assertEqual(w.start, utc(2026, 1, 1, 16))
        self.assertEqual(w.end, utc(2026, 1, 2, 16))

    def test_ambiguous_fold_night_is_covered(self):
        # Berlin falls back on 2026-10-25: 02:30 local exists at 00:30Z and 01:30Z.
        rule_day = date(2026, 10, 25)
        for t in (utc(2026, 10, 24, 22, 30),   # 00:30 local
                  utc(2026, 10, 25, 0, 30),    # 02:30 local, first pass
                  utc(2026, 10, 25, 1, 30)):   # 02:30 local, repeated pass
            self.assertTrue(local_rule_contains(rule_day, time(0), time(4), BERLIN, t))
        eng = self._engine(start_local=time(0), end_local=time(4), zone=BERLIN)
        def allowed(t):
            return eng.evaluate(PolicyContext("push", "F", "APT", "T", t, {})).allowed
        self.assertFalse(allowed(utc(2026, 10, 25, 1, 30)))
        self.assertTrue(allowed(utc(2026, 10, 25, 3, 30)))    # 04:30/05:30 local, over

    def test_spring_gap_instant_is_covered_when_rule_spans_it(self):
        # Berlin springs forward 2026-03-29 02:00 -> 03:00. Rule 01:30-03:30
        # must still cover the skipped wall clock minute (02:00 local == 01:00Z).
        w = local_rule_window(date(2026, 3, 29), time(1, 30), time(3, 30), BERLIN)
        self.assertEqual(w.start, utc(2026, 3, 29, 0, 30))
        self.assertEqual(w.end, utc(2026, 3, 29, 1, 30))
        self.assertTrue(w.contains(utc(2026, 3, 29, 1, 0)))


class CrossEngineConsistencyTests(unittest.TestCase):
    def test_notam_and_policy_never_disagree_on_same_night(self):
        # The same Friday 22:00-06:00 Shanghai rule expressed in both engines
        # must agree at every minute of Friday daytime..Saturday evening.
        effective = Window(utc(2025, 12, 1), utc(2026, 3, 1))
        notam_reg = NotamRegistry([Notam(
            "N", "rwy", "18", effective, 10, "prohibited",
            Recurrence(frozenset({4}), time(22), time(6), SH),
        )])
        pol = PolicyEngine([PolicyRule(
            "P", 10, frozenset(), Effect.DENY, "curfew",
            start_local=time(22), end_local=time(6), zone=SH)])
        tick = utc(2026, 1, 1, 22)          # Fri 06:00 local
        end = utc(2026, 1, 3, 10)           # Sat 18:00 local
        disagreements = []
        while tick < end:
            nd = notam_reg.decision("rwy", "18", Window(tick, tick + timedelta(minutes=1)))
            pd = pol.evaluate(PolicyContext("any", "F", "APT", "T", tick, {}))
            if nd.accepted != pd.allowed:
                disagreements.append(tick)
            tick += timedelta(minutes=10)
        self.assertEqual(disagreements, [])


if __name__ == "__main__":
    unittest.main()
