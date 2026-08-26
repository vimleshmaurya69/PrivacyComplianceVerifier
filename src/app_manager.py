import json
from pathlib import Path


class AppManager:

    def __init__(self, app_name):

        self.app_name = app_name

        self.base_path = (
            Path("data")
            / "apps"
            / app_name
        )

        self.config_file = (
            self.base_path
            / "app_config.json"
        )

        self.output_path = (
            Path("data")
            / "output"
            / app_name
        )

    # --------------------------------------------------
    # Load Application Configuration
    # --------------------------------------------------

    def load_config(self):

        if not self.config_file.exists():

            raise FileNotFoundError(
                f"Application configuration not found: "
                f"{self.config_file}"
            )

        with open(
            self.config_file,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    # --------------------------------------------------
    # Application Name
    # --------------------------------------------------

    def get_app_name(self):

        config = self.load_config()

        return config.get(
            "app_name",
            self.app_name
        )

    # --------------------------------------------------
    # Package Name
    # --------------------------------------------------

    def get_package_name(self):

        config = self.load_config()

        return config.get(
            "package_name",
            ""
        )

    # --------------------------------------------------
    # Application Services
    # --------------------------------------------------

    def get_application_services(self):

        config = self.load_config()

        return config.get(
            "application_services",
            []
        )
    def get_third_party_services(self):

        config = self.load_config()

        return config.get(
            "third_party_services",
            []
        )

    # --------------------------------------------------
    # HAR File
    # --------------------------------------------------

    def get_har_file(self):

        config = self.load_config()

        return (
            self.base_path
            / config["har_file"]
        )

    # --------------------------------------------------
    # Policy File
    # --------------------------------------------------

    def get_policy_file(self):

        config = self.load_config()

        return (
            self.base_path
            / config["policy_file"]
        )

    # --------------------------------------------------
    # Output Directory
    # --------------------------------------------------

    def get_output_path(self):

        self.output_path.mkdir(
            parents=True,
            exist_ok=True
        )

        return self.output_path

    # --------------------------------------------------
    # Display Configuration
    # --------------------------------------------------

    def display_config(self):

        print("=" * 60)
        print("Application Configuration")
        print("=" * 60)

        print(
            f"App Name      : "
            f"{self.get_app_name()}"
        )

        print(
            f"Package Name  : "
            f"{self.get_package_name()}"
        )

        print(
            f"HAR File      : "
            f"{self.get_har_file()}"
        )

        print(
            f"Policy File   : "
            f"{self.get_policy_file()}"
        )

        print(
            "\nApplication Services:"
        )

        for service in self.get_application_services():

            print(
                f"  - {service}"
            )


if __name__ == "__main__":

    manager = AppManager("forecastie")

    manager.display_config()