import unittest

from src.app_manager import AppManager
from src.filter.traffic_filter import TrafficFilter
from src.models.request import Request


class AppConfigurationTests(unittest.TestCase):

    @staticmethod
    def request(domain):
        return Request(
            method="GET",
            url=f"https://{domain}/",
            domain=domain,
            status=200,
            mime_type="text/plain",
        )

    def test_telegram_domains_are_application_traffic(self):
        manager = AppManager("telegram")
        config = manager.load_config()
        samples = [
            self.request("web.telegram.org"),
            self.request("zws1.web.telegram.org"),
            self.request("t.me"),
        ]
        TrafficFilter(
            samples,
            manager.get_app_name(),
            config["application_services"],
            config["third_party_services"],
        ).classify_requests()
        self.assertEqual(
            ["Application", "Application", "Application"],
            [sample.traffic_type for sample in samples],
        )

    def test_frida_file_resolution_honors_config_and_case(self):
        vlc_path = AppManager("VLC").get_frida_file()
        instagram_path = AppManager("Instagram").get_frida_file()
        self.assertTrue(vlc_path.exists())
        self.assertEqual("frida_evidence.json", vlc_path.name)
        self.assertTrue(instagram_path.exists())
        self.assertEqual("Frida", instagram_path.parent.name)


if __name__ == "__main__":
    unittest.main()
