#!/usr/bin/env python3
"""Judge an Autobahn testsuite run from its index.json.

usage: autobahn-check.py <reports-dir>/index.json

Acceptable case outcomes:
  behavior:      OK, NON-STRICT, INFORMATIONAL, UNIMPLEMENTED
  behaviorClose: OK, INFORMATIONAL, UNIMPLEMENTED

Anything else (FAILED, WRONG CODE, UNCLEAN, timeouts) fails the run and
is listed with its case id so the HTML report can be pulled up directly.
Exit 0 only when every case of every agent is acceptable.
"""

import json
import sys
from collections import Counter

OK_BEHAVIOR = {"OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"}
OK_CLOSE = {"OK", "INFORMATIONAL", "UNIMPLEMENTED"}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as handle:
        index = json.load(handle)

    failures = []
    tally: Counter = Counter()
    for agent, cases in sorted(index.items()):
        for case_id, result in sorted(cases.items()):
            behavior = result.get("behavior", "MISSING")
            close = result.get("behaviorClose", "MISSING")
            tally[behavior] += 1
            if behavior not in OK_BEHAVIOR or close not in OK_CLOSE:
                failures.append(
                    f"{agent} case {case_id}: behavior={behavior} "
                    f"close={close} report={result.get('reportfile', '?')}"
                )

    for line in failures:
        print(f"FAIL  {line}")
    print(f"agents: {len(index)}  cases: {sum(tally.values())}  "
          f"by behavior: {dict(sorted(tally.items()))}")
    if failures:
        print(f"{len(failures)} unacceptable case(s)")
        return 1
    print("autobahn: ALL CASES ACCEPTABLE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
