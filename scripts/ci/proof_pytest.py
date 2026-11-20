"""Run one proof test file under pytest and report a result by exit code.

Exit codes:
  10  pytest exited 0, at least one test passed its call phase, and none
      failed, errored, skipped, or xfailed (xfail and xpass both count).
  11  pytest exited 1, at least one test failed its call phase, and none
      errored (setup or teardown failure) or xfailed.
  3   every other case: collection error, skip, xfail, xpass, no tests,
      wrong argument count, or any other pytest exit code.

Exit codes 10 and 11 (not 0 and 1) mean a test that calls os._exit(0) or
os._exit(1) gives an unexpected code, which the caller maps to an error.
"""
import sys

import pytest


class Counter:
    def __init__(self):
        self.passed = self.failed = self.errors = self.skipped = self.xfail = 0

    def pytest_runtest_logreport(self, report):
        if hasattr(report, "wasxfail"):
            self.xfail += 1
        elif report.failed:
            if report.when == "call":
                self.failed += 1
            else:
                self.errors += 1
        elif report.skipped:
            self.skipped += 1
        elif report.when == "call" and report.passed:
            self.passed += 1


def main(argv):
    if len(argv) != 2:
        return 3
    counter = Counter()
    rc = pytest.main([argv[1], "-q", "-p", "no:cacheprovider"], plugins=[counter])
    if rc == 0 and counter.passed >= 1 and counter.failed == 0 and counter.errors == 0 and counter.skipped == 0 and counter.xfail == 0:
        return 10
    if rc == 1 and counter.failed >= 1 and counter.errors == 0 and counter.xfail == 0:
        return 11
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
