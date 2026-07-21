"""
run_all_pipeline_tests.py
=========================
Executes every AI SOC pipeline regression test sequentially and reports
pass / fail for each scenario.

Usage (from the project root):
    python -m tests.run_all_pipeline_tests
"""

import importlib
import sys
import traceback


# -------------------------------------------------
# Ordered list of test modules (relative to the
# tests package) and their human-readable labels.
# -------------------------------------------------

TESTS = [
    ("tests.test_pipeline_01_bruteforce",       "test_pipeline_01_bruteforce"),
    ("tests.test_pipeline_02_malware_download", "test_pipeline_02_malware_download"),
    ("tests.test_pipeline_03_successful_login", "test_pipeline_03_successful_login"),
    ("tests.test_pipeline_04_log4shell",        "test_pipeline_04_log4shell"),
    ("tests.test_pipeline_05_benign_login",     "test_pipeline_05_benign_login"),
    ("tests.test_pipeline_06_portscan",         "test_pipeline_06_portscan"),
    ("tests.test_pipeline_07_ransomware",       "test_pipeline_07_ransomware"),
    ("tests.test_pipeline_08_sql_injection",    "test_pipeline_08_sql_injection"),
    ("tests.test_pipeline_09_xss",              "test_pipeline_09_xss"),
    ("tests.test_pipeline_10_data_exfiltration","test_pipeline_10_data_exfiltration"),
]


SEPARATOR = "=" * 60


def run_test(module_path: str, label: str) -> bool:
    """
    Import the test module and call its main() function.

    Returns True on success, False on any exception.
    """

    print(f"\n{SEPARATOR}")
    print(f"Running {label}")
    print(SEPARATOR)

    try:

        module = importlib.import_module(module_path)

        module.main()

        print(f"\n[PASS] {label}")

        return True

    except Exception:

        print(f"\n[FAIL] {label}")
        traceback.print_exc()

        return False


def main():

    results = {}

    for module_path, label in TESTS:

        results[label] = run_test(module_path, label)

    # -------------------------------------------------
    # Summary
    # -------------------------------------------------

    print(f"\n\n{SEPARATOR}")
    print("REGRESSION SUITE SUMMARY")
    print(SEPARATOR)

    passed = 0
    failed = 0

    for label, ok in results.items():

        status = "PASS" if ok else "FAIL"

        print(f"  [{status}]  {label}")

        if ok:
            passed += 1
        else:
            failed += 1

    print(SEPARATOR)
    print(f"  Total: {len(results)}  |  Passed: {passed}  |  Failed: {failed}")
    print(SEPARATOR)

    # Exit with non-zero code if any test failed so CI can detect failures.

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
