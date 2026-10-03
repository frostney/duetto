#!/usr/bin/env python3
"""Judge an Autobahn testsuite run from its index.json.

usage: autobahn-check.py [--direction {client,server}] <reports-dir>/index.json

--direction names which side of duetto the report judges: `client` for
the fuzzingserver run against wsautobahn, `server` for the fuzzingclient
run against wsecho. It is printed with the verdict, so a log says which
direction passed or failed.

Acceptable case outcomes:
  behavior:      OK, INFORMATIONAL, UNIMPLEMENTED, and NON-STRICT except
                 in the client direction
  behaviorClose: OK, INFORMATIONAL, UNIMPLEMENTED

The client direction fails on NON-STRICT: its last seven such cases
were fixed in duetto#72, so one coming back is a regression. The server
direction, and a run judged without --direction, still accept it.

Anything else (FAILED, WRONG CODE, UNCLEAN, timeouts) fails the run and
is listed with its case id so the HTML report can be pulled up directly.
Exit 0 only when every case of every agent is acceptable.
"""

import argparse
import json
import sys
from collections import Counter

OK_BEHAVIOR = {"OK", "NON-STRICT", "INFORMATIONAL", "UNIMPLEMENTED"}
OK_BEHAVIOR_STRICT = OK_BEHAVIOR - {"NON-STRICT"}
OK_CLOSE = {"OK", "INFORMATIONAL", "UNIMPLEMENTED"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Judge an Autobahn testsuite run from its index.json.")
    parser.add_argument("--direction", choices=("client", "server"),
                        help="which side of duetto the report judges")
    parser.add_argument("index", help="<reports-dir>/index.json")
    args = parser.parse_args()

    ok_behavior = (OK_BEHAVIOR_STRICT if args.direction == "client"
                   else OK_BEHAVIOR)
    label = args.direction or "unspecified"

    with open(args.index, encoding="utf-8") as handle:
        index = json.load(handle)

    failures = []
    tally: Counter = Counter()
    for agent, cases in sorted(index.items()):
        for case_id, result in sorted(cases.items()):
            behavior = result.get("behavior", "MISSING")
            close = result.get("behaviorClose", "MISSING")
            tally[behavior] += 1
            if behavior not in ok_behavior or close not in OK_CLOSE:
                failures.append(
                    f"{agent} case {case_id}: behavior={behavior} "
                    f"close={close} report={result.get('reportfile', '?')}"
                )

    for line in failures:
        print(f"FAIL  {line}")
    print(f"direction: {label}  agents: {len(index)}  "
          f"cases: {sum(tally.values())}  "
          f"by behavior: {dict(sorted(tally.items()))}")
    if failures:
        print(f"{len(failures)} unacceptable case(s)")
        return 1
    print(f"autobahn ({label}): ALL CASES ACCEPTABLE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
