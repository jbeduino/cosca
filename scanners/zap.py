import os
import json
from scanner import Scanner


class CustomScanner(Scanner):
    NAME = "zap"
    DOCKER_IMAGE = "zaproxy/zap-stable"
    DEFECTDOJO_IMPORT_FORMAT = "ZAP Scan"
    REPORT_FILE_NAME = f"scan_results_{NAME}.json"
    REPORT_FILE_NAME_XML = f"scan_results_{NAME}.xml"
    REPORT_FILE_NAME_HTML = f"scan_results_{NAME}.html"
    CONTAINER_TARGET_DIRECTORY = "/src"
    CONTAINER_REPORT_DIRECTORY = "/zap/wrk"
    CONTAINER_REPORT_FILE = f"{CONTAINER_REPORT_DIRECTORY}/{REPORT_FILE_NAME}"


    def scan(self, target, working_dir, outputs):
        self.logger.info("Starting to scan target: %s", target)
        command = f'zap-baseline.py -t {target} -r {self.REPORT_FILE_NAME_HTML} -J {self.REPORT_FILE_NAME} -x {self.REPORT_FILE_NAME_XML}'
        volumes={working_dir: {
                'bind': self.CONTAINER_REPORT_DIRECTORY, 'mode': 'rw'}}
        logs = self.run_container(
            self.DOCKER_IMAGE, command, volumes)
        report_path_xml = f"{working_dir}/{self.REPORT_FILE_NAME_XML}"
        self.report_path = f"{working_dir}/{self.REPORT_FILE_NAME}"
        output_files = []
        for o in outputs:
            o.process_stdout(logs)
            output_files.append(o.process_files(
                report_path_xml, target, self.NAME, self.get_aux_args()))
        return output_files


    def get_findings_count(self, json_file):
        findings_count=[0,0,0,0,0,0]
        with open(json_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
        for a in data["site"][0]["alerts"]:
            i=int(a["riskcode"])
            findings_count[i]=findings_count[i]+1
        return findings_count


    def get_aux_args(self):
        return {'defectdojo_format': self.DEFECTDOJO_IMPORT_FORMAT,
                'json_findings': self.get_findings_count(self.report_path)
                }
