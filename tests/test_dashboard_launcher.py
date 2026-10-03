from pathlib import Path

import run_dashboard


def test_safe_child_rejects_parent_traversal(tmp_path):
    root = (tmp_path / "data").resolve()
    root.mkdir()

    assert run_dashboard._safe_child(root, "analysis/results.json") == (
        root / "analysis" / "results.json"
    )
    assert run_dashboard._safe_child(root, "../secret.txt") is None


def test_dashboard_handler_blocks_data_path_traversal():
    handler = object.__new__(run_dashboard.DashboardHandler)

    translated = Path(handler.translate_path("/data/../main.py"))

    assert translated == run_dashboard.DENIED_PATH
    assert translated != run_dashboard.ROOT_DIR / "main.py"


def test_dashboard_handler_routes_generated_data():
    handler = object.__new__(run_dashboard.DashboardHandler)

    translated = Path(handler.translate_path("/data/analysis/master_results.json"))

    assert translated == run_dashboard.DATA_DIR / "analysis" / "master_results.json"


def test_dashboard_handler_blocks_raw_app_capture_files():
    handler = object.__new__(run_dashboard.DashboardHandler)

    translated = Path(
        handler.translate_path("/data/apps/Truecaller/har/truecaller.har")
    )

    assert translated == run_dashboard.DENIED_PATH


def test_dashboard_handler_allows_sanitized_output_files():
    handler = object.__new__(run_dashboard.DashboardHandler)

    translated = Path(
        handler.translate_path("/data/output/Truecaller/compliance_results.json")
    )

    assert translated == (
        run_dashboard.DATA_DIR
        / "output"
        / "Truecaller"
        / "compliance_results.json"
    )
