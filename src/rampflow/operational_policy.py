from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from enum import Enum
from typing import Iterable, Mapping

from .timeutil import utc, wall_time_active


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE = "require"


@dataclass(frozen=True)
class PolicyContext:
    operation: str
    flight_id: str
    airport: str
    terminal: str
    at: datetime
    attributes: Mapping[str, object]

    def __post_init__(self):
        object.__setattr__(self, "at", utc(self.at))


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    priority: int
    operations: frozenset[str]
    effect: Effect
    reason: str
    required_attribute: str | None = None
    required_value: object | None = None
    terminal: str | None = None
    airport: str | None = None
    start_local: time | None = None
    end_local: time | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    zone: str = "UTC"
    weekdays: frozenset[int] | None = None

    def __post_init__(self):
        if self.valid_from is not None:
            object.__setattr__(self, "valid_from", utc(self.valid_from))
        if self.valid_until is not None:
            object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("invalid policy validity")
        if (self.start_local is None) != (self.end_local is None):
            raise ValueError("start_local and end_local must be set together")
        if self.weekdays is not None:
            if not self.weekdays or any(d < 0 or d > 6 for d in self.weekdays):
                raise ValueError("weekdays must use 0..6 (Monday..Sunday)")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    matched_rules: tuple[str, ...]
    requirements: tuple[str, ...]
    reasons: tuple[str, ...]
    revision: int = 0


class PolicyEngine:
    def __init__(self, rules: Iterable[PolicyRule] = ()):
        self.rules: dict[str, PolicyRule] = {}
        self.revision = 0
        for rule in rules:
            self.add(rule)

    def add(self, rule: PolicyRule) -> None:
        if rule.rule_id in self.rules:
            raise ValueError("duplicate policy rule")
        self.rules[rule.rule_id] = rule
        self.revision += 1

    def remove(self, rule_id: str) -> bool:
        if rule_id not in self.rules:
            return False
        del self.rules[rule_id]
        self.revision += 1
        return True

    def replace_rules(self, rules: Iterable[PolicyRule]) -> int:
        """Atomically swap the whole rule set.

        Validation happens against the proposed set first; on any conflict the
        active rules stay untouched, so a partially applied revision can never
        be observable.
        """
        next_rules: dict[str, PolicyRule] = {}
        for rule in rules:
            if rule.rule_id in next_rules:
                raise ValueError(f"duplicate policy rule {rule.rule_id}")
            next_rules[rule.rule_id] = rule
        self.rules = next_rules
        self.revision += 1
        return self.revision

    def _time_matches(self, rule: PolicyRule, ctx: PolicyContext) -> bool:
        if rule.valid_from is not None and ctx.at < rule.valid_from:
            return False
        if rule.valid_until is not None and ctx.at >= rule.valid_until:
            return False
        if rule.start_local is None:
            return True
        return wall_time_active(
            ctx.at, rule.start_local, rule.end_local, rule.zone, rule.weekdays
        )

    def _matches(self, rule: PolicyRule, ctx: PolicyContext) -> bool:
        if rule.operations and ctx.operation not in rule.operations:
            return False
        if rule.airport is not None and rule.airport != ctx.airport:
            return False
        if rule.terminal is not None and rule.terminal != ctx.terminal:
            return False
        if not self._time_matches(rule, ctx):
            return False
        if rule.required_attribute is not None:
            if rule.required_attribute not in ctx.attributes:
                return False
            if rule.required_value is not None and ctx.attributes[rule.required_attribute] != rule.required_value:
                return False
        return True

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        matched = [r for r in self.rules.values() if self._matches(r, ctx)]
        matched.sort(key=lambda r: (-r.priority, r.rule_id))
        denies = [r for r in matched if r.effect == Effect.DENY]
        requirements = [r for r in matched if r.effect == Effect.REQUIRE]
        allows = [r for r in matched if r.effect == Effect.ALLOW]
        unsatisfied = []
        for rule in requirements:
            marker = f"requirement:{rule.rule_id}"
            if not bool(ctx.attributes.get(marker, False)):
                unsatisfied.append(rule)
        if denies:
            allowed = False
        elif unsatisfied:
            allowed = False
        elif allows:
            allowed = True
        else:
            allowed = True
        reasons = tuple(r.reason for r in denies + unsatisfied)
        return PolicyDecision(
            allowed,
            tuple(r.rule_id for r in matched),
            tuple(r.rule_id for r in requirements),
            reasons,
            self.revision,
        )

    def explain(self, ctx: PolicyContext) -> Mapping[str, object]:
        decision = self.evaluate(ctx)
        return {
            "operation": ctx.operation,
            "flight_id": ctx.flight_id,
            "allowed": decision.allowed,
            "matched_rules": decision.matched_rules,
            "requirements": decision.requirements,
            "reasons": decision.reasons,
            "revision": decision.revision,
        }
