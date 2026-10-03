from pathlib import Path

import main as framework_main


class _MissingHarAppManager:
    def __init__(self, _app_name, tmp_path):
        self.tmp_path = tmp_path

    def get_app_name(self):
        return "Missing HAR"

    def get_har_file(self):
        return self.tmp_path / "missing.har"

    def get_policy_file(self):
        return self.tmp_path / "missing-policy.json"

    def get_output_path(self):
        return self.tmp_path / "output"


class _SyntheticAppManager:
    def __init__(self, _app_name, tmp_path):
        self.tmp_path = tmp_path
        self.fixture = Path("data/apps/DummyTestApp")

    def get_app_name(self):
        return "Dummy Test App (Synthetic)"

    def get_har_file(self):
        return self.fixture / "har" / "dummy_test.har"

    def get_policy_file(self):
        return self.fixture / "policy" / "dummy_test_policy.json"

    def get_output_path(self):
        output = self.tmp_path / "output"
        output.mkdir(parents=True, exist_ok=True)
        return output

    def get_application_services(self):
        return ["dummy.test"]

    def get_third_party_services(self):
        return []

    def get_frida_file(self):
        return self.tmp_path / "missing-frida.json"


def test_missing_har_returns_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        framework_main,
        "AppManager",
        lambda app_name: _MissingHarAppManager(app_name, tmp_path),
    )

    assert framework_main.main("Missing") == 1


def test_comparator_failure_removes_stale_result(monkeypatch, tmp_path):
    manager = _SyntheticAppManager("Dummy", tmp_path)
    stale_result = manager.get_output_path() / "compliance_results.json"
    stale_result.write_text('{"stale": true}', encoding="utf-8")
    monkeypatch.setattr(
        framework_main,
        "AppManager",
        lambda app_name: _SyntheticAppManager(app_name, tmp_path),
    )

    def fail_comparison(_self):
        raise RuntimeError("synthetic comparator failure")

    monkeypatch.setattr(
        framework_main.PolicyComparator,
        "compare",
        fail_comparison,
    )

    assert framework_main.main("Dummy") == 1
    assert not stale_result.exists()
