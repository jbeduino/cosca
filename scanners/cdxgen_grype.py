import os
import sys
import json
from scanner import Scanner


class CustomScanner(Scanner):
    """
    Grype (https://github.com/anchore/grype) for 
    cdxgen (https://github.com/CycloneDX/cdxgen) SBOM scanner for Combo Scanner
    """
    NAME = "cdxgen_grype"
    DOCKER_IMAGE = "anchore/grype"
    SBOM_IMAGE = "ghcr.io/cyclonedx/cdxgen"
    DEFECTDOJO_IMPORT_FORMAT = "Anchore Grype"
    SBOM_FILE_NAME_JSON = "sbom.json"
    SBOM_FILE_NAME_TABLE = "sbom.txt"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"

    def scan(self, target, working_dir, outputs):
        self.logger.info("Generating SBOM...")
        sbom_path_table = f"{working_dir}/{self.SBOM_FILE_NAME_TABLE}"
        command = f"-r {self.CONTAINER_TARGET_DIRECTORY} \
        -o {self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME_JSON} -p"
        volumes = {target: {'bind': self.CONTAINER_TARGET_DIRECTORY, 'mode': 'rw'},
                   working_dir: {'bind': self.CONTAINER_REPORT_DIRECTORY,
                                 'mode': 'rw'}}
        logs_1 = self.run_container(self.SBOM_IMAGE, command, volumes)
        try:
            with open(f'{sbom_path_table}', 'w', encoding='utf-8') as f:
                f.write(logs_1)
        except (FileNotFoundError, PermissionError):
            self.logger.error(
                "Could't create output file in host %s", self.report_path)
            sys.exit(1)
        self.logger.info("Scanning SBOM...")
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME_JSON} -o table"
        volumes = {working_dir: {
            'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs_2 = self.run_container(self.DOCKER_IMAGE, command, volumes)
        self.logger.info("Generating SBOM file...")
        self.report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        command = f"sbom:{self.CONTAINER_REPORT_DIRECTORY}/{self.SBOM_FILE_NAME_JSON} -o json"
        volumes = {working_dir: {
            'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs_3 = self.run_container(self.DOCKER_IMAGE, command, volumes)
        try:
            with open(f'{self.report_path}', 'w', encoding='utf-8') as f:
                f.write(logs_3)
        except (FileNotFoundError, PermissionError):
            self.logger.error(
                "Could't create output file in host %s", self.report_path)
            sys.exit(1)
        output_files = []
        for o in outputs:
            o.process_stdout(logs_1 + "\n" + logs_2)
            output_files.append(o.process_files(
                self.report_path, target, self.NAME, self.get_aux_args()))
        return output_files

    def get_findings_count(self, json_file):
        severity_index = {"Negligible": 0, "Low": 1,
                          "Medium": 2, "High": 3, "Critical": 4, "Unknown": 5}
        findings_count = [0, 0, 0, 0, 0, 0]
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        for v in data["matches"]:
            i = severity_index[v["vulnerability"]["severity"]]
            findings_count[i] = findings_count[i]+1
        return findings_count

    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }
