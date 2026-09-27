import iam_scanner


def test_package_imports():
    assert iam_scanner.CIS_BENCHMARK_VERSION == "3.0.0"
