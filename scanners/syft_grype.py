import sys
import json
from scanner import Scanner
from common.target_type import TargetType


class CustomScanner(Scanner):
    """
    Grype (https://github.com/anchore/grype) for
    Syft (https://github.com/anchore/syft) SBOM scanner for Combo Scanner
    """

    NAME = "syft_grype"
    DOCKER_IMAGE = "anchore/grype"
    SBOM_IMAGE = "anchore/syft"
    SBOM_FILE_NAME_JSON = "sbom.json"
    SBOM_FILE_NAME_TABLE = "sbom.txt"
    DEFECTDOJO_IMPORT_FORMAT = "Anchore Grype"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    ACCEPTED_TARGET_TYPES = [TargetType.DIRECTORY]

    def scan(self, target, working_dir, outputs, network):
        self.logger.info("Generating SBOM...")
        sbom_path_json = f"{working_dir}/{self.SBOM_FILE_NAME_JSON}"
        sbom_path_table = f"{working_dir}/{self.SBOM_FILE_NAME_TABLE}"
        command = f"scan dir:{self.CONTAINER_TARGET_DIRECTORY} -o table --source-name artifact_dir --source-version 1.0"
        volumes = {target: {"bind": self.CONTAINER_TARGET_DIRECTORY, "mode": "rw"}}
        logs_1 = self.run_container(self.SBOM_IMAGE, command, volumes)
        self.logger.info("Creating SBOM table file...")
        try:
            with open(f"{sbom_path_table}", "w", encoding="utf-8") as f:
                f.write(logs_1)
        except (FileNotFoundError, PermissionError):
            self.logger.error("Could't create output file in host %s", sbom_path_table)
            sys.exit()
        command = f"scan dir:{self.CONTAINER_TARGET_DIRECTORY} -o json --source-name artifact_dir --source-version 1.0"
        volumes = {target: {"bind": self.CONTAINER_TARGET_DIRECTORY, "mode": "rw"}}
        logs_2 = self.run_container(self.SBOM_IMAGE, command, volumes)
        self.logger.info("Creating SBOM json file...")
        try:
            with open(f"{sbom_path_json}", "w", encoding="utf-8") as f:
                f.write(logs_2)
        except (FileNotFoundError, PermissionError):
            self.logger.error("Could't create output file in host %s", sbom_path_json)
            sys.exit()
        self.logger.info("Scanning SBOM...")
        report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME_JSON}"
        volumes = {working_dir: {"bind": self.CONTAINER_REPORT_DIRECTORY, "mode": "rw"}}
        logs_3 = self.run_container(self.DOCKER_IMAGE, command, volumes)
        self.logger.info("Generating report file...")
        self.report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME_JSON} --output json"
        logs_4 = self.run_container(self.DOCKER_IMAGE, command, volumes)
        try:
            with open(f"{report_path}", "w", encoding="utf-8") as f:
                f.write(logs_4)
        except (FileNotFoundError, PermissionError):
            self.logger.error("Could't create output file in host: %s", report_path)
            sys.exit(1)
        output_files = []
        for o in outputs:
            o.process_stdout(logs_1 + "\n" + logs_3)
            output_files.append(
                o.process_files(
                    self.report_path, target, self.NAME, self.get_aux_args()
                )
            )
        return output_files

    def get_findings_count(self, json_file):
        severity_index = {
            "Negligible": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4,
            "Unknown": 5,
        }
        findings_count = [0, 0, 0, 0, 0, 0]
        with open(json_file, "r", encoding="utf-8") as file:
            # print()
            data = json.load(file)
        for v in data["matches"]:
            i = severity_index[v["vulnerability"]["severity"]]
            findings_count[i] = findings_count[i] + 1
        return findings_count

    def get_aux_args(self):
        return {
            "defectdojo_format": self.DEFECTDOJO_IMPORT_FORMAT,
            "json_findings": self.get_findings_count(self.report_path),
        }
