"""Copy an allow-list of fields from a SARIF 2.1.0 file into a smaller file.

Usage: sarif_min.py [--drop-message] IN OUT

Standard library only. Nothing outside the allow-list reaches OUT: no rule
text, no snippet, no fingerprint, no absolute path. With --drop-message, no
result keeps its message. Exit 0 on success, 2 on a file that has the wrong
shape (one line on standard error, no output file).
"""
import argparse
import json
import os
import sys


class Shape(Exception):
    pass


def obj(parent, key, what):
    """Return parent[key] as a dict, or None when absent."""
    if key not in parent:
        return None
    v = parent[key]
    if not isinstance(v, dict):
        raise Shape(f"{what} must be an object")
    return v


def items(parent, key, what):
    """Return parent[key] as a list of objects; absent or null gives []."""
    v = parent.get(key)
    if v is None:
        return []
    if not isinstance(v, list):
        raise Shape(f"{what} must be a list")
    if not all(isinstance(x, dict) for x in v):
        raise Shape(f"{what} must hold objects")
    return v


def copy_leaves(src, keys, what, dest):
    for key in keys:
        if key in src:
            v = src[key]
            if isinstance(v, (dict, list)):
                raise Shape(f"{what}.{key} must be a scalar")
            dest[key] = v


def keep(dest, key, value):
    """Set dest[key] when value holds a field."""
    if value:
        dest[key] = value


def reduce_rule(rule):
    out = {}
    copy_leaves(rule, ("id",), "rule", out)
    cfg = obj(rule, "defaultConfiguration", "defaultConfiguration")
    if cfg is not None:
        d = {}
        copy_leaves(cfg, ("level",), "defaultConfiguration", d)
        keep(out, "defaultConfiguration", d)
    props = obj(rule, "properties", "rule properties")
    if props is not None:
        d = {}
        copy_leaves(props, ("security-severity",), "rule properties", d)
        keep(out, "properties", d)
    return out


def reduce_location(loc):
    out = {}
    phys = obj(loc, "physicalLocation", "physicalLocation")
    if phys is None:
        return out
    p = {}
    art = obj(phys, "artifactLocation", "artifactLocation")
    if art is not None:
        d = {}
        copy_leaves(art, ("uri",), "artifactLocation", d)
        keep(p, "artifactLocation", d)
    region = obj(phys, "region", "region")
    if region is not None:
        d = {}
        copy_leaves(region, ("startLine",), "region", d)
        keep(p, "region", d)
    keep(out, "physicalLocation", p)
    return out


def find_rule_position(result, rule_id, rules):
    """Place in rules of the rule of a result, as scanner.load_sarif finds it."""
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        return index
    if isinstance(rule_id, str):
        for i, r in enumerate(rules):
            if r.get("id") == rule_id:
                return i
    return None


def reduce_run(run, drop_message):
    """Return (reduced run, rules in the input, results in the input)."""
    out = {}
    tool = obj(run, "tool", "tool")
    rules = []
    if tool is not None:
        driver = obj(tool, "driver", "driver")
        if driver is not None:
            d = {}
            copy_leaves(driver, ("name", "version", "semanticVersion"), "driver", d)
            rules = items(driver, "rules", "rules")
            out["tool"] = {"driver": d}
    results = items(run, "results", "results")
    kept_rules, new_place, new_results = [], {}, []
    for result in results:
        r = {}
        copy_leaves(result, ("ruleId",), "result", r)
        rule_obj = obj(result, "rule", "result rule")
        if "ruleId" not in r and rule_obj is not None:
            copy_leaves(rule_obj, ("id",), "result rule", r)
            if "id" in r:
                r["ruleId"] = r.pop("id")
        pos = find_rule_position(result, r.get("ruleId"), rules)
        if pos is not None:
            if pos not in new_place:
                new_place[pos] = len(kept_rules)
                kept_rules.append(reduce_rule(rules[pos]))
            r["ruleIndex"] = new_place[pos]
        copy_leaves(result, ("level", "kind"), "result", r)
        message = obj(result, "message", "message")
        if message is not None and not drop_message:
            d = {}
            copy_leaves(message, ("text",), "message", d)
            keep(r, "message", d)
        locations = items(result, "locations", "locations")
        if locations:
            loc = reduce_location(locations[0])
            if loc:
                r["locations"] = [loc]
        new_results.append(r)
    if "tool" in out:
        out["tool"]["driver"]["rules"] = kept_rules
    out["results"] = new_results
    return out, len(rules), len(results)


def reduce_sarif(doc, drop_message):
    if not isinstance(doc, dict):
        raise Shape("top level must be an object")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not all(isinstance(r, dict) for r in runs):
        raise Shape("runs must be a list of objects")
    out = {}
    copy_leaves(doc, ("version",), "top level", out)
    out_runs, n_rules, n_results = [], 0, 0
    for run in runs:
        r, nr, nres = reduce_run(run, drop_message)
        out_runs.append(r)
        n_rules += nr
        n_results += nres
    out["runs"] = out_runs
    return out, len(runs), n_rules, n_results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--drop-message", action="store_true")
    ap.add_argument("input")
    ap.add_argument("output")
    a = ap.parse_args(argv)
    try:
        with open(a.input, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        print(f"sarif_min: cannot read input: {type(e).__name__}", file=sys.stderr)
        return 2
    try:
        out, runs, n_rules, n_results = reduce_sarif(doc, a.drop_message)
    except Shape as e:
        print(f"sarif_min: bad shape: {e}", file=sys.stderr)
        return 2
    try:
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(out, f, separators=(",", ":"))
            f.write("\n")
    except OSError as e:
        print(f"sarif_min: cannot write output: {type(e).__name__}", file=sys.stderr)
        return 2
    print(f"sarif_min: {os.path.basename(a.output)} runs={runs} rules={n_rules} results={n_results}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
