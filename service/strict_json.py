"""Dependency-free strict JSON parsing shared by every service boundary.

Duplicate keys are rejected so that two parsers can never disagree about which
value a request "really" carried.
"""
import json


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(_):
    raise ValueError('non-standard JSON constant')


def loads(text):
    """Parse JSON rejecting duplicate keys and NaN/Infinity."""
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=_reject_constant)
