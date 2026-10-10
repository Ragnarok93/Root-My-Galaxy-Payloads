#!/usr/bin/env python3
"""Extract actionable Samsung Kbuild warnings/errors from very verbose V=1 logs.

Read-only. No source/config/build artifacts changed. Matches Samsung's custom
('error, forbidden warning:', 'filename:line') to original Clang diagnostics
even when parallel Kbuild jobs interleave their output.
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

DIAGNOSTIC = re.compile(
    r"^(?P<source>.+?\.(?:c|h|S|cc|cpp)):"
    r"(?P<line>\d+)(?::(?P<column>\d+))?:\s*"
    r"(?P<level>warning|error|fatal error):\s*(?P<message>.*)$"
)
FATAL_WRAPPER = re.compile(
    r"""(?:\('error, forbidden warning:',\s*'(?P<location>[^']+)'\))"""
)
MAKE_ERROR = re.compile(
    r"^(?:(?:make(?:\[\d+\])?):\s+\*\*\*|(?:clang|ld|as):\s+error:|/usr/bin/ld:\s+)"
)
CATEGORY = re.compile(r"\[(-W[\w=-]+)\]\s*$")


def scan_log(path, limit=20):
    """Return structured summary, including all forbidden-warning categories."""
    if not path.is_file():
        raise ValueError("build log does not exist: " + str(path))
    diagnostics = []
    forbidden = []
    errors = []
    warnings_count = 0
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, raw in enumerate(source, start=1):
            line = raw.rstrip("\n")
            warning_match = DIAGNOSTIC.match(line)
            if warning_match:
                item = warning_match.groupdict()
                item["line"] = int(item["line"])
                item["logLine"] = line_number
                item["category"] = (
                    CATEGORY.search(item["message"]).group(1)
                    if CATEGORY.search(item["message"]) else None
                )
                diagnostics.append(item)
                if item["level"] == "warning":
                    warnings_count += 1
                continue
            wrapper = FATAL_WRAPPER.search(line)
            if wrapper:
                location = wrapper.group("location")
                filename, _, lineno = location.rpartition(":")
                candidates = [
                    d for d in diagnostics
                    if d["source"].rsplit("/", 1)[-1] == filename.rsplit("/", 1)[-1]
                    and str(d["line"]) == lineno
                    and d["logLine"] < line_number
                ]
                match = candidates[-1] if candidates else None
                forbidden.append({
                    "location": location, "logLine": line_number,
                    "diagnostic": match,
                    "resolved": match is not None
                })
                continue
            if MAKE_ERROR.search(line):
                errors.append({"logLine": line_number, "text": line[:600]})
    occurrences = Counter(
        entry["diagnostic"]["category"] or "<unknown-category>"
        for entry in forbidden if entry["diagnostic"] is not None
    )
    return {
        "log": str(path),
        "warningCount": warnings_count,
        "forbiddenWarningCount": len(forbidden),
        "forbiddenWarningCategories": dict(occurrences.most_common()),
        "forbiddenWarnings": forbidden[:limit],
        "otherDiagnostics": [
            entry for entry in diagnostics if entry["level"] != "warning"
        ][:limit],
        "buildErrors": errors[:limit],
        "unresolvedForbiddenWarnings": sum(not x["resolved"] for x in forbidden),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--max-items", type=int, default=20)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.max_items < 1 or args.max_items > 200:
        parser.error("--max-items must be between 1 and 200")
    try:
        result = scan_log(args.log.expanduser(), args.max_items)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print("Build log:", result["log"])
    print("Compiler warning lines:", result["warningCount"])
    print("Samsung-forbidden warnings:", result["forbiddenWarningCount"])
    for error in result["forbiddenWarnings"]:
        diagnostic = error["diagnostic"]
        print("  FAIL:", error["location"], "at log line", error["logLine"])
        if diagnostic:
            print("    Compiler:", diagnostic["source"] + ":" +
                  str(diagnostic["line"]), "|", diagnostic["category"] or "unnamed")
            print("    Warning:", diagnostic["message"])
            print("    Diagnostic at log line:", diagnostic["logLine"])
        else:
            print("    Compiler warning unavailable in this log")
    if result["otherDiagnostics"]:
        print("Other compiler errors:")
        for item in result["otherDiagnostics"]:
            print("  ", item["source"] + ":" + str(item["line"]),
                  item["message"][:240])
    if result["buildErrors"]:
        print("Build termination errors:")
        for item in result["buildErrors"][:5]:
            print("  ", item["text"][:240])
    if args.json:
        with args.json.expanduser().open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
        print("Saved:", args.json)


if __name__ == "__main__":
    main()
