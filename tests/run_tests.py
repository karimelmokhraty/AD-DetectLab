#!/usr/bin/env python3
"""
Evaluate the Sigma rules in detections/ against saved log samples.

Why this exists
---------------
A detection rule that stops working fails silently. You tune it to cut false
positives, the noise goes away, you ship it -- and you never notice it also
stopped catching the attack. Nothing tells you until the day it mattered.

So every rule is pinned to two samples: one containing the real attack (the
rule MUST match it) and one of ordinary domain traffic (the rule MUST NOT
match it). Break either direction and this script fails the build.

This is not theoretical. The first run of these tests found two rules that
matched everything in the normal-traffic baseline -- including one whose
condition was always true and fired on every service ticket request in the
domain. Both had been reviewed by eye and looked fine.

How it works
------------
Rules are parsed by pySigma itself -- the same library `sigma convert` uses --
so detection items, modifiers, condition logic and correlation references are
interpreted exactly as the Sigma spec defines them. Implemented here is only
the evaluation: does an event match a leaf comparison, and does a group of
events satisfy a correlation.

Usage:  python tests/run_tests.py [path/to/manifest.yml]
Exit:   0 = all rules behave, 1 = at least one rule does not
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SpecialChars

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# leaf matching
# --------------------------------------------------------------------------

def sigma_string_to_regex(value) -> re.Pattern:
    """Turn a SigmaString into an anchored, case-insensitive regex.

    Sigma modifiers are already wildcards by the time they reach us:
    `field|endswith: $` parses to the SigmaString [WILDCARD_MULTI, '$'], and
    `|contains` / `|startswith` work the same way. Handling wildcards here
    therefore covers every modifier these rules use, with no special cases.
    """
    out = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            out.append(re.escape(str(part)))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def field_matches(event: dict, field: str, value) -> bool:
    """Does `event[field]` match this Sigma value?"""
    actual = event.get(field)
    if actual is None:
        return False

    # Numbers compare numerically, so 4769 and "4769" are the same event.
    if hasattr(value, "number"):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return False

    if hasattr(value, "s"):
        return bool(sigma_string_to_regex(value).match(str(actual)))

    return str(actual).lower() == str(value).lower()


# --------------------------------------------------------------------------
# condition tree evaluation
# --------------------------------------------------------------------------

def evaluate(node, event: dict) -> bool:
    """Walk a parsed pySigma condition tree against a single event."""
    if isinstance(node, ConditionAND):
        return all(evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return field_matches(event, node.field, node.value)

    raise NotImplementedError(
        f"{type(node).__name__} is not supported by this runner yet. "
        f"Add support for it here rather than loosening a rule to fit."
    )


def matching_events(rule: SigmaRule, events: list[dict]) -> list[dict]:
    trees = []
    for condition in rule.detection.parsed_condition:
        condition.detections = rule.detection.detections
        trees.append(condition.parse())
    return [e for e in events if any(evaluate(t, e) for t in trees)]


# --------------------------------------------------------------------------
# correlation evaluation
# --------------------------------------------------------------------------

def event_time(event: dict) -> datetime:
    raw = event.get("_time") or event.get("timestamp") or event.get("@timestamp")
    if raw is None:
        raise ValueError(
            "correlation rules need a timestamp on every event; "
            f"none of _time / timestamp / @timestamp present in {event!r}"
        )
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


OPERATORS = {
    "lt": lambda v, n: v < n,
    "lte": lambda v, n: v <= n,
    "gt": lambda v, n: v > n,
    "gte": lambda v, n: v >= n,
    "eq": lambda v, n: v == n,
}


def correlation_hits(corr: SigmaCorrelationRule, events: list[dict]) -> list[tuple]:
    """Return the (group, time-bucket, measured value) tuples that fire.

    Mirrors what the generated SPL does: select events with the referenced
    base rule, floor timestamps into fixed buckets the width of `timespan`,
    group by the group-by fields, then compare the aggregate.
    """
    kind = str(corr.type).rsplit(".", 1)[-1].lower()
    if kind not in ("event_count", "value_count"):
        raise NotImplementedError(
            f"correlation type '{kind}' is not implemented in this runner. "
            f"Implement it here rather than weakening the rule."
        )

    # Events selected by every referenced base rule.
    selected: list[dict] = []
    for ref in corr.rules:
        base = ref.rule
        if isinstance(base, SigmaCorrelationRule):
            raise NotImplementedError("chained correlation rules are not supported yet")
        selected.extend(matching_events(base, events))

    span = corr.timespan.seconds
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for event in selected:
        bucket = int(event_time(event).timestamp()) // span * span
        key = tuple(event.get(f) for f in corr.group_by) + (bucket,)
        groups[key].append(event)

    op = OPERATORS[str(corr.condition.op).rsplit(".", 1)[-1].lower()]
    threshold = corr.condition.count

    hits = []
    for key, bucket_events in groups.items():
        if kind == "event_count":
            measured = len(bucket_events)
        else:
            fieldref = corr.condition.fieldref
            measured = len({
                e[fieldref] for e in bucket_events if e.get(fieldref) is not None
            })
        if op(measured, threshold):
            hits.append((key[:-1], key[-1], measured))
    return hits


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def load_json(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else [data]


def count_for(collection: SigmaCollection, events: list[dict]) -> tuple[int, str]:
    """Evaluate a rule file against events.

    If the file contains a correlation rule, that correlation IS the detection
    and the base rules it references are only inputs to it -- a base rule is
    expected to match ordinary traffic, which is why it is not alertable on
    its own.
    """
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    if correlations:
        total = sum(len(correlation_hits(c, events)) for c in correlations)
        return total, "correlation group(s) fired"

    plain = [r for r in collection.rules if isinstance(r, SigmaRule)]
    total = sum(len(matching_events(r, events)) for r in plain)
    return total, "event(s) matched"


def main() -> int:
    manifest_path = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "tests" / "manifest.yml"
    )
    manifest = yaml.safe_load(manifest_path.read_text())
    base_dir = manifest_path.parent

    negative = load_json(base_dir / manifest["negative_sample"])
    print(f"negative sample: {manifest['negative_sample']} ({len(negative)} events)\n")

    failures: list[str] = []

    for entry in manifest["tests"]:
        rule_path = REPO / entry["rule"]
        name = rule_path.name
        wanted = entry.get("min_matches", 1)
        standalone = entry.get("standalone", True)

        collection = SigmaCollection.load_ruleset([str(rule_path)])
        positive = load_json(base_dir / entry["positive"])

        hits, unit = count_for(collection, positive)
        noise, _ = count_for(collection, negative)

        ok_positive = hits >= wanted
        ok_negative = (noise == 0) or not standalone

        print(f"[{'PASS' if ok_positive and ok_negative else 'FAIL'}] {name}")
        print(f"         attack sample : {hits} {unit} (need >= {wanted})")
        print(
            f"         normal traffic: {noise} {unit} "
            f"({'need 0' if standalone else 'not alertable alone - see reason'})"
        )
        if not standalone:
            reason = " ".join(entry.get("reason", "no reason given").split())
            print(f"         NOT STANDALONE: {reason}")
            if "reason" not in entry:
                failures.append(
                    f"{name}: marked standalone: false without a `reason` -- "
                    f"an untested rule must say why in the manifest"
                )

        if not ok_positive:
            failures.append(
                f"{name}: matched only {hits} in the attack sample, expected at least "
                f"{wanted} -- the rule misses the technique it is meant to catch"
            )
        if standalone and noise:
            failures.append(
                f"{name}: matched {noise} ordinary events -- the rule is too broad and "
                f"would fire on normal domain activity"
            )
        print()

    print("=" * 72)
    if failures:
        print(f"{len(failures)} problem(s) found:\n")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"All {len(manifest['tests'])} rule files behave on both samples.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
