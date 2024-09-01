import os
from pathlib import Path
import json
from scanner import Scanner
from common.converter import JUnit2Sarif


class CustomScanner(Scanner):
    """ Dastardly (https://portswigger.net/burp/dastardly) for Combo Scanner """
    NAME = "dastardly"
    DOCKER_IMAGE = "public.ecr.aws/portswigger/dastardly:latest"
    DEFECTDOJO_IMPORT_FORMAT = "SARIF"
    REPORT_FILE_NAME_XML = f"scan_results_{NAME}.xml"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/tmp"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME_XML}"

    def scan(self, target, working_dir, outputs):
        self.logger.info("Starting to scan target: %s", target)
        command = ""
        volumes = {working_dir: {
            'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        environment = {'DASTARDLY_TIMEOUT': '300', 'BURP_TIMEOUT': '300',
                       'BURP_START_URL': f'{target}', 'BURP_REPORT_FILE_PATH': f'{self.CONTAINER_REPORT_FILE}'}
        logs = self.run_container(
            self.DOCKER_IMAGE, command, volumes, environment, user=f'{os.getuid()}')
        report_path_xml = f"{working_dir}/{self.REPORT_FILE_NAME_XML}"
        report_path_sarif = Path(
            report_path_xml).with_suffix('.json').as_posix()
        self.logger.debug("Custom scanning completed.")
        self.logger.info("Scan report generated: %s", report_path_xml)
        JUnit2Sarif().convert(report_path_xml, report_path_sarif)
        self.report_path = report_path_sarif
        output_files = []
        for o in outputs:
            o.process_stdout(logs)
            output_files.append(o.process_files(
                report_path_sarif, target, self.NAME, self.get_aux_args()))
        return output_files

    def get_findings_count(self, json_file):
        severrity_index = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}
        findings_count = [0, 0, 0, 0, 0, 0]
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        for r in data["runs"][0]["tool"]["driver"]["rules"]:
            i = severrity_index[r["properties"]["impact"]
                            [0].split("\n")[0].split(" ")[1]]
            findings_count[i] = findings_count[i]+1
        return findings_count

    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }
